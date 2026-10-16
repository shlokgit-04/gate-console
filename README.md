# Gate Console — trust review dashboard for AI agents

A UI/UX design prototype for the Hyperbloom October UI/UX & Web Design hackathon.

Gate Console is the human side of an agent-safety gate: when an AI agent wants to
perform a consequential action (send a payment, send an email, call an external
API), the gate holds it in an approval queue with the evidence a human needs to
decide in seconds.

## Screens
1. **Approval queue** — pending agent tool calls with the gate's verdict on each.
2. **Decision detail** — why the gate held one action: the injected instruction
   found in a retrieved invoice, the policy that fired, and clear approve/block paths.
3. **Audit log** — every decision, immutable.
4. **Policy settings** — the knobs behind the gate (wire ceilings, cooling periods).

## Design decisions
- Dark, high-contrast theme tuned for long review sessions; AA-contrast text.
- Evidence is quoted as untrusted data, visually separated from agent intent.
- Verdict pills (block / review / pass) carry one meaning each, color + label.
- Keyboard reachable: rows and toggles are focusable and operable without a mouse.
- No backend needed: it is a working front-end prototype with demo data.

Built as a static HTML/CSS/JS prototype. Demo data is synthetic; no real payments,
inboxes, or agents are involved.
