"""Gate Console: the human side of an agent-safety gate.

When an AI agent wants to perform a consequential action, the gate holds it
in an approval queue with the evidence a human needs to decide in seconds.
This app is the real console: accounts, a per-user queue, a server-side
policy engine, and an immutable audit log.

All demo data is synthetic. No real payments, inboxes or agents are involved.
"""
import re

from flask import (Flask, g, jsonify, redirect, render_template, request,
                   url_for)

from accounts import (GateStore, check_password, evaluate, hash_password,
                      rate_limited, valid_email)

app = Flask(__name__)
store = GateStore()

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; "
        "script-src 'self'; connect-src 'self'; frame-ancestors 'none'"),
}


@app.after_request
def set_security_headers(resp):
    for k, v in _SECURITY_HEADERS.items():
        resp.headers.setdefault(k, v)
    return resp


def current_user():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    if not token:
        token = request.cookies.get("gc_token", "")
    return store.verify(token)


def require_user():
    user = current_user()
    if user is None:
        return None, (jsonify({"error": "unauthorized"}), 401)
    return user, None


# -- pages --------------------------------------------------------------------
@app.get("/")
def console():
    if current_user() is None:
        return redirect(url_for("login_page"))
    return render_template("console.html")


@app.get("/login")
def login_page():
    return render_template("login.html")


@app.get("/register")
def register_page():
    return render_template("register.html")


@app.get("/privacy")
def privacy():
    return render_template("privacy.html")


@app.get("/about")
def about():
    return render_template("about.html")


# -- auth api -----------------------------------------------------------------
@app.post("/api/auth/register")
def api_register():
    if rate_limited(request.remote_addr or "?"):
        return jsonify({"error": "rate_limited"}), 429
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip()
    password = body.get("password") or ""
    if not valid_email(email):
        return jsonify({"error": "invalid_email"}), 400
    if len(password) < 8:
        return jsonify({"error": "weak_password"}), 400
    if store.user_by_email(email) is not None:
        return jsonify({"error": "email_taken"}), 409
    uid = store.create_user(email, hash_password(password))
    user = store.user_by_id(uid)
    token = store.issue(uid, user["token_version"])
    return jsonify({"email": email, "token": token})


@app.post("/api/auth/login")
def api_login():
    if rate_limited(request.remote_addr or "?"):
        return jsonify({"error": "rate_limited"}), 429
    body = request.get_json(silent=True) or {}
    user = store.user_by_email(body.get("email") or "")
    if user is None or not check_password(body.get("password") or "",
                                          user["pw_hash"]):
        return jsonify({"error": "invalid_credentials"}), 401
    return jsonify({"email": user["email"],
                    "token": store.issue(user["id"], user["token_version"])})


@app.get("/api/auth/me")
def api_me():
    user, err = require_user()
    if err:
        return err
    return jsonify({"email": user["email"], "created_at": user["created_at"]})


@app.get("/api/auth/export")
def api_export():
    user, err = require_user()
    if err:
        return err
    return jsonify({"user": {"email": user["email"],
                             "created_at": user["created_at"]},
                    "policy": store.policy(user["id"]),
                    "actions": store.actions(user["id"]),
                    "audit": store.audit(user["id"])})


@app.delete("/api/auth/me")
def api_delete_me():
    user, err = require_user()
    if err:
        return err
    store.delete_user(user["id"])
    return jsonify({"status": "deleted"})


# -- gate api -----------------------------------------------------------------
@app.get("/api/queue")
def api_queue():
    user, err = require_user()
    if err:
        return err
    uid = user["id"]
    actions = store.actions(uid)
    pending = [a for a in actions if a["status"] == "pending"]
    decided = [a for a in actions if a["status"] == "decided"]
    blocked = [a for a in actions if a["verdict"] == "BLOCK"]
    stats = {
        "pending": len(pending),
        "blocked_total": len(blocked),
        "auto_passed": len([a for a in actions if a["verdict"] == "PASS"]),
        "review_total": len([a for a in actions if a["verdict"] == "REVIEW"]),
    }
    return jsonify({"stats": stats, "pending": pending, "decided": decided})


@app.get("/api/queue/<int:action_id>")
def api_action(action_id):
    user, err = require_user()
    if err:
        return err
    a = store.action(user["id"], action_id)
    if a is None:
        return jsonify({"error": "not_found"}), 404
    return jsonify(a)


@app.post("/api/queue/<int:action_id>/decide")
def api_decide(action_id):
    user, err = require_user()
    if err:
        return err
    body = request.get_json(silent=True) or {}
    decision = (body.get("decision") or "").strip().lower()
    note = (body.get("note") or "").strip()[:500]
    if decision not in ("approved", "blocked", "escalated"):
        return jsonify({"error": "bad_decision"}), 400
    a = store.action(user["id"], action_id)
    if a is None:
        return jsonify({"error": "not_found"}), 404
    if not store.decide(user["id"], action_id, decision):
        return jsonify({"error": "already_decided"}), 409
    store.log(user["id"], decision.upper(),
              f"{a['agent']} {a['action']} — human decision: {decision}"
              + (f" ({note})" if note else ""))
    return jsonify({"status": "recorded", "decision": decision})


@app.post("/api/simulate")
def api_simulate():
    """Submit a synthetic agent action; the server-side gate evaluates it."""
    user, err = require_user()
    if err:
        return err
    if rate_limited("sim:" + (request.remote_addr or "?")):
        return jsonify({"error": "rate_limited"}), 429
    body = request.get_json(silent=True) or {}
    agent = (body.get("agent") or "").strip()
    action = (body.get("action") or "").strip()
    target = (body.get("target") or "").strip()
    context = (body.get("context") or "").strip()
    if not agent or not action or not target:
        return jsonify({"error": "missing_fields"}), 400
    verdict, flags = evaluate(store, user["id"], agent, action, target,
                              context)
    aid = store.add_action(user["id"], agent, action, target, verdict,
                           context)
    kind = {"BLOCK": "BLOCK", "REVIEW": "HOLD", "PASS": "AUTO"}[verdict]
    store.log(user["id"], kind,
              f"{agent} {action} — gate verdict {verdict}"
              + (f" ({len(flags)} flag(s))" if flags else " (clean)"))
    return jsonify({"id": aid, "verdict": verdict, "flags": flags})


@app.get("/api/audit")
def api_audit():
    user, err = require_user()
    if err:
        return err
    return jsonify({"items": store.audit(user["id"])})


@app.get("/api/policy")
def api_policy_get():
    user, err = require_user()
    if err:
        return err
    return jsonify(store.policy(user["id"]))


@app.put("/api/policy")
def api_policy_put():
    user, err = require_user()
    if err:
        return err
    body = request.get_json(silent=True) or {}
    cur = store.policy(user["id"])
    p = {
        "wire_ceiling": cur["wire_ceiling"],
        "treat_docs_as_data": cur["treat_docs_as_data"],
        "payee_cooling_days": cur["payee_cooling_days"],
        "egress_allowlist": cur["egress_allowlist"],
    }
    try:
        if "wire_ceiling" in body:
            p["wire_ceiling"] = int(body["wire_ceiling"])
        if "payee_cooling_days" in body:
            p["payee_cooling_days"] = int(body["payee_cooling_days"])
        for k in ("treat_docs_as_data", "egress_allowlist"):
            if k in body:
                p[k] = bool(body[k])
    except (TypeError, ValueError):
        return jsonify({"error": "bad_policy"}), 400
    if not (0 <= p["wire_ceiling"] <= 1_000_000
            and 0 <= p["payee_cooling_days"] <= 60):
        return jsonify({"error": "bad_policy"}), 400
    if not store.set_policy(user["id"], p):
        return jsonify({"error": "no_policy_row"}), 500
    store.log(user["id"], "POLICY", f"policy updated: {p}")
    return jsonify(store.policy(user["id"]))


@app.get("/api/health")
def api_health():
    return jsonify({"ok": True, "service": "gate-console"})


_URL_RE = re.compile(r"https?://")
