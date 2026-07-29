# opsgate threat model

This document states what opsgate defends against, how, and where the limits are.
If you are evaluating whether to point an agent at production, read the
[Non-goals](#non-goals) section first.

## Assets

1. **Availability of the managed hosts** — an agent restarting or stopping the wrong
   service is the most likely real incident.
2. **Secrets readable on those hosts** — private keys, `.env` files, database credentials.
3. **The audit trail** — if it can be edited silently, it is worthless during an incident review.
4. **The SSH credential** opsgate holds.

## Adversaries

| # | Adversary | Capability |
|---|---|---|
| A1 | **A confused agent** | Calls the wrong tool with plausible arguments. No malice; the most common case. |
| A2 | **A prompt-injected agent** | An attacker controls text the model reads — a log line, an HTML page, a commit message — and steers it toward destructive or exfiltrating calls. |
| A3 | **A malicious client** | Speaks MCP directly to opsgate and crafts arbitrary tool arguments, ignoring any model-level guidance. |
| A4 | **A network attacker** | Sits between opsgate and a managed host, or reaches the HTTP transport port. |
| A5 | **An insider covering tracks** | Has filesystem access and wants to remove evidence of a command from the audit log. |

A3 is the design baseline: opsgate assumes tool arguments are attacker-controlled.
Nothing in the safety model depends on the model behaving well.

## Controls

### C1 — Structured tools (defeats argument injection)

Agents cannot supply commands, only typed arguments to a fixed tool set. Commands are
assembled as `[]string` argv:

```go
argv := []string{"systemctl", "restart", in.Name}
```

The local executor passes argv to `exec.Command` — no shell process exists. The SSH
executor must produce a string for the remote shell, so it single-quotes every element
(`internal/executor.ShellQuote`), making each element exactly one shell word.

`nginx; touch /tmp/pwned` as a service name therefore reaches `systemctl` as a single
literal argument, and fails as an unknown unit. It does not start a second command.
`executor_test.go` asserts this empirically by round-tripping injection payloads through
a real shell.

Secondary containment: `policy.ValidTarget` restricts service/container/unit names to
`[A-Za-z0-9@:._/-]`, and `file_grep` uses `grep -F` so patterns are never regexes.

### C2 — Deny-by-default policy (bounds A1 and A2)

Every call is classified `Observe`, `Mutate`, or `Shell` at registration time, and checked
against the effective mode before execution:

| | observe | operate | full |
|---|---|---|---|
| Observe tools | allow | allow | allow |
| Mutate tools | **deny** | approval | allow |
| shell_exec | **deny** | approval | approval¹ |

¹ unless explicitly set to `approval: never`.

Modes are per-host, so production can be `observe` while staging is `operate`.
`allow_targets` narrows a tool to specific objects — `service_restart` limited to
`["nginx", "myapp*"]` cannot touch `sshd` in any mode, at any approval level.
`enabled: false` removes a tool from the listing entirely, so the agent never sees it.

### C3 — Human approval (bounds A2 and A3)

In `operate`, mutating calls block on MCP elicitation showing the tool, host, a
plain-language summary, and the exact command. Approval is per-call; there is no
"remember this" path.

This is the control that specifically addresses prompt injection: a compromised agent can
*request* a restart, but a human sees the request before it happens.

If the client does not support elicitation, the call fails closed with an explanatory
error — it does not silently proceed.

### C4 — Path allowlist (protects secrets)

`file_read`, `dir_list`, and `file_grep` accept only paths under `files.allow_paths`.
Paths are `path.Clean`ed *before* the prefix comparison, so traversal is resolved and then
rejected:

- `/var/log/../../etc/shadow` → cleans to `/etc/shadow` → refused
- `/var/logsomething/x` → refused (the prefix must end at a path boundary)

Defaults are `/var/log`, `/etc/nginx`, `/etc/systemd` — deliberately not `/`, and
deliberately not `$HOME`.

**Known limitation:** the check is lexical. A symlink *inside* an allowed directory that
points outside it will be followed by the remote `cat`. If your allowed paths are
writable by untrusted users, treat that as a hole.

### C5 — Hash-chained audit log (defeats A5)

Each record embeds `prev_hash`, the SHA-256 of the preceding record. `opsgate audit verify`
walks the file and reports the first line where the chain breaks. Editing a record,
deleting one, or reordering two all invalidate everything downstream.

Denials are logged with the same weight as successes.

**Known limitation:** the chain is tamper-*evident*, not tamper-*proof*. Someone who can
write the file can rewrite the whole chain from any point and produce a self-consistent
log. Ship the log off-box (or to append-only storage) if that adversary is in scope.
Recording only the SHA-256 of command output, not the output itself, keeps secrets read
during an incident out of the log.

### C6 — Transport security (bounds A4)

SSH host keys are verified against `~/.ssh/known_hosts`; there is no
`InsecureIgnoreHostKey` and no trust-on-first-use. An unrecognised host key aborts the
connection with instructions to record it deliberately.

The HTTP transport requires a bearer token when `http.auth_token` is set, compared without
early exit on mismatch. If it is unset, opsgate prints a warning at startup — it does not
silently serve unauthenticated. TLS is not built in; terminate it upstream.

### C7 — Resource bounds

Per-command timeout (default 30s) with SSH sessions signalled and closed on expiry so a
hung remote command cannot pin a connection. Output is capped
(`max_output_bytes`, default 48 KiB) with explicit truncation notice; `lines`-style
arguments are clamped server-side regardless of what the agent requests.

## Non-goals

**opsgate is not a sandbox.** Approved commands run for real, with your SSH user's
privileges. If that user is root, an approved call is a root call. Create a dedicated user
with only the `sudoers` entries the tools need.

**opsgate does not make an untrusted agent safe for production.** It shrinks blast radius
and creates an audit trail. A prompt-injected agent can still call permitted tools with
plausible arguments — `service_restart("nginx")` is indistinguishable from a legitimate
request. Policy scope is your real bound; keep `allow_targets` narrow.

**`full` mode has no human control.** It is for environments where you accept unattended
mutation.

**`shell_exec`, when enabled, is RCE by design.** It exists because the structured tool set
will never cover everything. Leave it off; enable it per-host when you must.

**Availability is not protected.** Nothing prevents an agent from calling allowed
read-only tools in a loop and loading the host.

## Reporting a vulnerability

Open a GitHub security advisory on the repository rather than a public issue.
