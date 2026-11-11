# Contributing to Watchtower

Thank you for considering a contribution.

## Principles

1. **Human-in-the-loop is non-negotiable.** Do not add automatic blocking, deletion, reporting, or any autonomous action.
2. **No network calls from the core.** Telemetry, update checks, or "phone-home" features will be rejected.
3. **Transparency over cleverness.** Scores must remain explainable. Opaque ML verdicts belong elsewhere.
4. **No writing-style / typo / "AI-ness" scoring.** This is excluded by design.
5. **Keep the core stdlib-only** unless there is a compelling, reviewed reason otherwise.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
python tests/test_smoke.py
python harness.py --help
```

## Pull requests

- One logical change per PR.
- Update docs if you change behavior or add a signal kind.
- Add or extend a smoke test when practical.
- Never commit secrets, real baselines containing sensitive paths, or production databases.


## AI music / DAW MCP scanner

- Treat JSON-RPC logs and scanned source as untrusted input; never execute them.
- Do not decode audio during scanning. Use only file size and supplied metadata.
- Label static-analysis results as indicators, not proof of exploitability.
- Keep the scanner stdlib-only and advisory-only.
- Preserve source event identifiers and session IDs when present; never fabricate them.
- MCP review records require a reviewer-entered session ID and rationale.

- CLAP and WAV scanners must remain read-only: never load a plugin, decode audio, or execute a binary to obtain metadata.
- Keep WAV parsing bounded to headers/chunk metadata; treat malformed fields and call bursts as indicators, not proof of a crash.
- Do not claim a plugin is malicious based only on a hash, filename, embedded string, or bundle size.
