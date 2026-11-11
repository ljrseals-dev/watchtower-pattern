# Part 0 — Threat model in one table

| Adversary move | Browser agent surface | Desktop harness surface | Detection signal | Harness adapter |
|----------------|-----------------------|-------------------------|------------------|-----------------|
| Prompt injection / instruction override | Web content → agent context | Clipboard, file text, stdin | `input_injection_pattern` | InputAnomaly |
| Encoded payload smuggling | URL params, form fields, data: URIs | Env vars, argv, filenames | `input_encoded_payload` | InputAnomaly |
| Bidi / control-char spoofing | Display name, filename rendering | Log forgery, path confusion | `input_control_characters` | InputAnomaly |
| Trojanized binary / dropped file | Downloaded attachment | Persistence, startup folder | `file_added`, `file_modified` | FileIntegrity |
| Permission escalation on disk | Profile dir, extension dir | `~/.config`, `chmod +x` | `file_permission_change` | FileIntegrity |
| Credential brute force | Login flows, API keys | sshd, sudo, PAM | `auth_failure_burst` | AuthLog |
| Novel command-and-control source | New CDN, new API origin | New outbound peer | `auth_new_source` | AuthLog |
| Privilege use / lateral shell | Devtools → shell bridge | sudo, pkexec, setuid | `auth_privilege_change` | AuthLog |

Everything that follows is the remediation catalog that turns those signals into a program rather than a screenshot.
