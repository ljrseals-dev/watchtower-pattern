# Part 3 — The Cross-Cutting Remediation Stack

These apply to both halves and are where most programs actually fail.

| Layer | Remediation | Harness hook |
|-------|-------------|--------------|
| Identity | Least privilege, per-task identity, no shared service accounts | `auth_privilege_change`, `auth_new_source` |
| Input | Validate at every boundary; reject by default; no eval/shell | `InputAnomalyAdapter` |
| Detection | Typed signals, explained scores, no opaque verdicts | `Signal` / `Finding` dataclasses |
| Response | Human review, advisory tiers, no autonomous action | `RESPONSE_TIERS`, `cmd_review` |
| Audit | Append-only, hash-chained, written before scoring | `AuditLog.append` |
| Data | Hashes + metadata, not file bodies; local only | `sha256_file`, no network calls |
| Access | Config perms checked at startup | `check_config_permissions` |
| Governance | No automated decisions (GDPR Art. 22) | Decisions are human choices |
| Retention | Purge closed findings past policy | `cmd_purge` |
| Integrity | Verify the log chain | `cmd_verify` |

## 3.1 Response tiers — and why they are text, not triggers

| Score | Tier | Guidance (advisory only) |
|-------|------|--------------------------|
| ≥ 0.85 | critical | Review immediately. Consider isolating the path by hand. |
| ≥ 0.65 | high | Review today. Corroborate before acting. |
| ≥ 0.45 | medium | Review this week. Low urgency alone. |
| < 0.45 | low | Record only. |

The harness prints these. It does not execute them. That distinction is the entire point: an advisory tier that fires an action is no longer advisory. The moment a tool auto-blocks, it becomes a denial-of-service vector for anyone who can generate a finding — and a liability for anyone who can't appeal it.

## 3.2 What the harness will never do (and why that's the feature)

- **No network calls, no telemetry.** A detection tool with a phone-home is an exfiltration tool with extra steps.
- **No screen capture, no keystroke logging.** Those are surveillance primitives, not security primitives, and they create evidence you then have to protect.
- **No writing-style or typo scoring.** Invalid signal, disparate impact. Excluded by design, stated in the docstring, enforced by the fact that the code simply isn't there.
- **No automatic block / delete / report.** Human-in-the-loop is not a fallback; it's the architecture.
- **No contacting anyone.** Escalation writes a row and prints a sentence. The human process lives outside the tool, where it can be governed, audited, and appealed.
