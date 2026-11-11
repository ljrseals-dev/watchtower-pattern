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

# AI music / DAW MCP request logs and static skill checks (read-only)
python harness.py scan --mcp-log mcp-events.jsonl --daw-profile daw_profile.json
python harness.py scan --music-scan-dir ./skills --daw-profile daw_profile.json

# CLAP plugin inventory + WAV header / repeated audio-call checks (read-only)
python harness.py scan --clap-scan-dir /path/to/clap/plugins
python harness.py scan --audio-scan-dir /path/to/audio-or-wav-folder
python harness.py scan --audio-call-log audio-calls.jsonl

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

## Threat model and detection signals

Watchtower's threat model maps adversary behavior to observable signals and reviewable findings. The following examples describe the intended detection vocabulary; a signal is evidence for review, not a verdict that an incident occurred.

| Adversary move / risk | Example signal or surface |
|-----------------------|---------------------------|
| Prompt injection or instruction override | `input_injection_pattern` |
| Encoded payload smuggling through URL parameters, environment variables, or argv | `input_encoded_payload` |
| Bidirectional or control-character spoofing | `input_control_characters` |
| Unexpected or modified executable/file | `file_added`, `file_modified` |
| Permission escalation on disk | `file_permission_change` |
| New or unexpected authentication source | `auth_new_source` |
| MCP tool-call path traversal / output-path escape | `ai_music_mcp` findings |
| Audio resource exhaustion or suspicious caption text | `ai_music_mcp` findings |
| CLAP bundle integrity, symlink, or unusual-footprint indicators | `clap_audio` findings |
| Malformed/extreme WAV headers or repeated audio-call bursts | `clap_audio` findings |

The browser-agent, desktop-harness, and cross-cutting remediation documents remain the project-wide control catalog. The AI music/DAW and CLAP/WAV checks are additional read-only detection surfaces feeding the same human review workflow; they do not replace the core adapters or remediation guidance.

---

## AI music, DAW, CLAP, and audio surfaces

The optional music/audio checks extend the existing detection-and-review model to DAW-adjacent agent tooling:

- **MCP logs and static skill files:** inspect supplied JSON-RPC tool-call logs and static source for path-boundary, audio-resource, mixed-script caption, package-pinning, and control-endpoint indicators.
- **CLAP bundles:** inventory `.clap` directories, record bounded SHA-256 hashes for conventional plugin binaries, collect limited printable metadata strings, and flag symlinks or unusual layouts/footprints.
- **WAV files:** inspect bounded RIFF/RF64 header and chunk metadata for malformed bounds or extreme parameters. Audio samples are not decoded.
- **Audio-call logs:** identify bursts of timestamped WAV/audio/render/import/decode operations grouped by session and tool.

Example commands:

```bash
python harness.py scan --mcp-log mcp-events.jsonl --daw-profile daw_profile.json
python harness.py scan --music-scan-dir ./skills --daw-profile daw_profile.json
python harness.py scan --clap-scan-dir /path/to/clap/plugins
python harness.py scan --audio-scan-dir /path/to/audio-or-wav-folder
python harness.py scan --audio-call-log audio-calls.jsonl
```

These are **indicators, not exploit confirmation**. A log record does not prove a tool call was accepted or executed; a burst does not prove a DAW crashed; a hash does not establish whether a plugin is trusted or malicious. The current audio checks do not monitor live audio callbacks, CPU load, xruns, memory pressure, or actual plugin crashes. CLAP metadata is not authoritatively identified by loading plugin entry points, and WAV inspection is not a complete RIFF/RF64 validator.

All specialized findings are advisory and enter the existing review/report path. The scanners do not load plugins, execute binaries, decode PCM, render audio, make network calls, install packages, control DAW processes, block, delete, quarantine, or disable plugins.

---

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
├── ai_music_mcp_scanner.py # Read-only MCP / AI music / DAW indicators
├── clap_audio_scanner.py   # Read-only CLAP inventory + WAV/audio-call indicators
├── README.md               # This file
├── LICENSE                 # MIT
├── requirements.txt        # Empty / optional (stdlib only for core)
├── docs/
│   ├── 00-threat-model.md
│   ├── 01-browser-agent-remediations.md
│   ├── 02-desktop-harness-remediations.md
│   ├── 03-cross-cutting-stack.md
│   ├── 04-operating-the-harness.md
│   ├── 05-honest-gaps.md
│   ├── 06-ai-music-daw-mcp.md
│   └── 07-clap-wav-audio.md
├── adapters/               # Placeholder for future extracted adapters
├── examples/
│   └── sample_auth.log
├── tests/
│   ├── test_smoke.py
│   ├── test_ai_music_mcp.py
│   └── test_clap_audio.py
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


## Research paper

The accompanying research manuscript, **“The Trust Boundary You Forgot You Had: Threats Posed by AI-Coded Plugins and DAW Workstations, and a Human-in-the-Loop Architecture for Stopping Them,”** is available in [`docs/the-trust-boundary-ai-coded-plugins-daw-workstations.md`](docs/the-trust-boundary-ai-coded-plugins-daw-workstations.md). Its incident claims and references are author-supplied and require independent source verification before external publication.
