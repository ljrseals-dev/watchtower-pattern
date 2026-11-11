# Part 2 — Desktop Application Harness Remediations

The desktop harness has the opposite problem from the browser: it is trusted by the OS and therefore inherits every privilege the user has. Remediation is about **shrinking that inheritance**.

## 2.1 Process-level isolation

- **Sandbox profile per app.** seccomp-bpf + Landlock on Linux, App Sandbox on macOS, AppContainer/Job Objects on Windows. Deny by default; open specific paths and syscalls.
- **No setuid, no setcap, no root.** If the harness needs privilege, it asks a separate privileged broker over a narrow IPC channel, and that broker logs.
- **Privilege separation by function.** The parser, the network client, the file writer, and the credential holder are separate processes with separate UIDs where feasible.
- **Resource limits.** CPU, memory, file descriptors, wall-clock. A runaway harness is an availability incident.

## 2.2 Filesystem integrity and least access

- Read-only mounts for everything the app does not need to write.
- Per-app writable directory, mode `0700`, no symlink following.
- Baseline + diff on every scan — this is exactly what `FileIntegrityAdapter` does. The baseline is the contract; the diff is the alarm.
- Permission-change detection is not optional. A `chmod 777` on a config file is a remediation trigger, not a shrug. `file_permission_change` weight (0.45) reflects that.

## 2.3 Shell and command execution

- **No `shell=True`.** No `os.system`. No `eval`. No `exec` of strings. This is not a style rule; it's the difference between a bug and a breach.
- **Argument vectors, not command strings.** If a subprocess is unavoidable, pass an argv list and validate every element against a strict allowlist.
- Wrap every external command in a thin shim that logs argv, cwd, env (redacted), exit code, and duration to the audit log.
- Detect shell-spawning from unexpected parents. A browser or document viewer spawning bash is an event worth a finding.

## 2.4 Credential and secret hygiene

- OS keychain / secret service only. No plaintext secrets in config, env, or argv.
- Mode `0600` on config, `0700` on the app directory. The harness already enforces this at startup and warns when `CONFIG_PATH` is group/world-readable — keep that check, and extend it to every file the app writes.
- Short-lived credentials. If the app must hold an API key, it holds a scoped, expiring one.
- Environment scrubbing. Child processes get a minimal env. No `LD_PRELOAD`, no `DYLD_INSERT_LIBRARIES`, no inherited `*_TOKEN`.

## 2.5 Update and supply-chain integrity

- Signed releases, verified signatures at install and at launch.
- Pinned dependencies with hash verification (`pip --require-hashes`, `npm ci`, lockfiles with integrity fields).
- No post-install scripts from untrusted packages. Review them or vendor the dependency.
- SBOM published per release. If you can't name your transitive deps, you can't remediate a CVE in them.

## 2.6 Audit and forensics

- Append-only, hash-chained log — the `AuditLog` class. Written before scoring, so a compromise that corrupts the scorer still leaves a trail.
- `verify` subcommand for chain integrity. Run it on a schedule and on every incident.
- Retention policy with purge — `cmd_purge` implements it. GDPR Art. 5(1)(e) storage limitation is a real obligation, not a checkbox.
- Reviewer attribution. Every decision records reviewer, rationale, timestamp. That's what makes the log defensible in an audit.
