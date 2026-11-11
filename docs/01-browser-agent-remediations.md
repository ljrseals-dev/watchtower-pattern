# Part 1 — Browser Online Agent Remediations

Browser agents are the harder half. The agent has a real session, real cookies, real form-fill authority, and — increasingly — real tool-call authority. Treat the browser as an **untrusted execution environment that happens to hold your credentials**.

## 1.1 Session and identity isolation

- **Dedicated browser profile per agent.** Never the user's daily-driver profile. No shared cookie jar, no shared extensions, no shared password manager.
- **Container or VM boundary.** The agent's browser lives in a disposable container. On exit, the container dies. Nothing persists except an explicit export directory.
- **Separate OS user.** On desktop, the agent runs as its own UID. File permissions then do the isolation work the browser cannot.
- **No SSO persistence.** Re-authenticate per session. Short-lived tokens only. The agent should not hold a refresh token that outlives the task.
- **Hardware-backed key custody.** If the agent must sign anything, the key lives in a TPM / Secure Enclave / OS keychain, never in page JS.

## 1.2 Action-scoping and capability gating

- **Allowlist of origins.** The agent may navigate to `*.example.com`. Any other origin is a hard stop that produces a finding, not a redirect.
- **Allowlist of verbs.** Read-only by default. `click`, `type`, `submit` are separately granted, separately logged, and reversible where possible.
- **Irreversible-action interlock.** Purchases, deletions, permission grants, outbound messages, and credential changes require an explicit human confirmation step *outside* the agent's own UI. The agent cannot dismiss its own dialog.
- **No shell bridge.** Devtools protocol, `chrome.debugger`, native messaging hosts, and "run this command" helper extensions are the top exfiltration path. Disable all of them. If a vendor requires one, wrap it and log every call.
- **Download policy.** Downloads land in a quarantine directory, are hashed, and are not auto-opened. The hash goes into FileIntegrity.

## 1.3 Prompt-injection defense in depth

No single control works. Stack them:

| Layer | Control | What it buys |
|-------|---------|--------------|
| Input | Spotlighting / delimiter injection around untrusted content | Model treats retrieved text as data, not instructions |
| Input | Encoded-run detection, control-char stripping | Kills base64/hex/bidi smuggling |
| Input | HTML/markdown sanitization before the model sees it | Kills invisible-text and zero-width payloads |
| Policy | Tool-call allowlist, no nested tool invocation | Limits blast radius when injection succeeds |
| Output | Structured output only; free-form text never executed | Prevents "the model said to run it" |
| Runtime | Egress allowlist at the network layer | Exfil needs a destination; deny the destination |
| Detection | InputAnomalyAdapter on every untrusted string | Queues the suspicious ones for a human |
| Governance | Human confirmation for irreversible verbs | The last honest gate |

> The harness deliberately does **not** score writing style, typos, or "AI-ness." That signal has zero validity for intent and reliably misfires on disabled users, non-native speakers, and anyone using an input method the scorer wasn't trained on. Excluding it is not a concession — it's the correct call.

## 1.4 Network egress control

- DNS allowlist at the resolver, not the browser. The browser cannot be trusted to enforce its own egress policy.
- TLS inspection or SNI logging on the agent's container. Every new SNI is an `auth_new_source`-class event.
- No raw sockets, no WebRTC, no QUIC fallback unless explicitly required and logged.
- Proxy with per-request attribution. If the agent makes a call, the proxy log knows which task made it.

## 1.5 Observability

- Full session capture (network, DOM mutations, tool calls) to an append-only store.
- Every tool call is a structured event with arguments, result, and the task ID that produced it.
- Replay capability. A finding without a replayable trace is a rumor. The trace is what makes the human review meaningful.
