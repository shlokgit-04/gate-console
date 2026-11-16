# Gate Console — trust review dashboard for AI agents

The human side of an agent-safety gate: when an AI agent wants to perform a
consequential action (send a payment, send an email, call an external API),
the gate holds it in an approval queue with the evidence a human needs to
decide in seconds.

Originally built as a UI/UX prototype for the Hyperbloom October hackathon,
now a full-stack app:

- **Real accounts** — per-reviewer sign-in, pbkdf2-hashed passwords, signed
  30-day session tokens with per-user token versioning.
- **Per-user queue and audit log** — agent actions, verdicts and decisions
  live in SQLite, scoped to your account, exportable, deletable.
- **Server-side policy engine** — injected-instruction detection in retrieved
  text, a wire ceiling, a payee cooling period and egress allow-list
  enforcement. The verdicts in the UI come from the server, not demo data.
- **Live policy knobs** — settings drive the gate immediately.

## Screens
1. **Approval queue** — pending agent tool calls with the gate's verdict on each, plus a submit form that runs synthetic actions through the gate live.
2. **Decision detail** — why the gate held one action and clear approve/block/escalate paths.
3. **Audit log** — every decision and auto-verdict, immutable.
4. **Policy settings** — the knobs behind the gate.

## Design decisions
- Dark, high-contrast theme tuned for long review sessions; AA-contrast text.
- Evidence is quoted as untrusted data, visually separated from agent intent.
- Verdict pills (block / review / pass) carry one meaning each, color + label.
- Keyboard reachable: rows and toggles are focusable and operable without a mouse.

All demo data is synthetic; no real payments, inboxes, or agents are involved.

Made by Shlok V. — https://shlok.is-a.dev
