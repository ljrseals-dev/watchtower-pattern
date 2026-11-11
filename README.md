# The Watchtower Pattern

**Exhaustive Security Remediation for Browser Agents and Desktop Harnesses — with a Human-in-the-Loop Detection Core**

> "The exploit is not the payload. The exploit is the trust boundary you forgot you had."  
> — every incident postmortem, eventually

---

## What this is

Watchtower is a **detection-and-review** system, not an enforcement system.

The core (`harness.py`) observes, scores, explains, and queues findings.  
**A human decides.** That is not a weakness. That is the only architecture that survives contact with a real SOC and a real legal department.

It targets two converging attack surfaces:

1. **Browser-resident online agents** — LLM-driven or automation-driven actors operating inside a real web session (cookies, form-fill authority, tool-call authority).
2. **Desktop application harnesses** — local processes that touch files, shells, credentials, and the network.

---

## Quick start

```bash
# Optional: create a virtualenv
python3 -m venv .venv && source .venv/bin/activate

# No third-party dependencies required for the core harness
python harness.py --help

# 1. Baseline a known-good state
python harness.py baseline /path/to/app /path/to/config

# 2. Scan (file integrity + optional input / auth-log adapters)
python harness.py scan /path/to/app
python harness.py scan --input suspicious_prompt.txt
python harness.py scan --auth-log /var/log/auth.log

# 3. Review open findings (forces reviewer name + rationale)
python harness.py review

# 4. Report / verify / purge
python harness.py report
python harness.py verify
python harness.py purge --days 90
```

Data lives under `~/.watchtower/` by default (`harness.db`, `baseline.json`).

---

## Design constraints (enforced by construction)

| Constraint | Why |
|------------|-----|
| No network calls / telemetry | A detection tool with a phone-home is an exfiltration tool with extra steps |
| No screen capture / keystroke logging | Surveillance primitives, not security primitives |
| No writing-style or "AI-ness" scoring | Invalid signal, disparate impact |
| No automatic block / delete / report | Human-in-the-loop is the architecture, not a fallback |
| No contacting anyone | Escalation writes a row and prints a sentence |
| Advisory tiers only | An advisory tier that fires an action is no longer advisory |

---

## Response tiers (advisory only)

| Score | Tier | Guidance |
|-------|------|----------|
| ≥ 0.85 | critical | Review immediately. Consider isolating the path by hand. |
| ≥ 0.65 | high | Review today. Corroborate before acting. |
| ≥ 0.45 | medium | Review this week. Low urgency alone. |
| < 0.45 | low | Record only. |

The harness prints these. It does **not** execute them.

---

## Repository layout

```
watchtower/
├── harness.py              # The detection core (CLI)
├── README.md               # This file
├── LICENSE                 # MIT
├── requirements.txt        # Empty / optional (stdlib only for core)
├── docs/
│   ├── 00-threat-model.md
│   ├── 01-browser-agent-remediations.md
│   ├── 02-desktop-harness-remediations.md
│   ├── 03-cross-cutting-stack.md
│   ├── 04-operating-the-harness.md
│   └── 05-honest-gaps.md
├── adapters/               # Placeholder for future extracted adapters
├── examples/
│   └── sample_auth.log
├── tests/
│   └── test_smoke.py
└── .github/workflows/
    └── ci.yml
```

---

## Full remediation surface

The markdown documents under `docs/` are the complete remediation catalog:

- **Part 0** — Threat model (one table)
- **Part 1** — Browser online agent remediations (session isolation, action-scoping, prompt-injection defense-in-depth, egress, observability)
- **Part 2** — Desktop application harness remediations (process isolation, filesystem integrity, shell safety, credential hygiene, supply-chain, audit)
- **Part 3** — Cross-cutting stack (identity, input, detection, response, audit, data, access, governance, retention, integrity)
- **Part 4** — Operating the harness like you mean it
- **Part 5** — Honest gaps (what the conference talks skip)

---

## What the harness will never do

- No network calls, no telemetry
- No screen capture, no keystroke logging
- No writing-style or typo scoring
- No automatic block / delete / report
- No contacting anyone

---

## License

MIT. See [LICENSE](LICENSE).

---

## Companion documents

If you need the operating-procedure companion (reviewer roles, on-call rotation, escalation paths, retention policy, incident-response runbook that plugs into `cmd_review`), open an issue or ask — it can be added under `docs/ops/`.
