<div align="center">

# opsgate

**The safety gate between AI agents and your servers.**

An MCP server that lets Claude, Cursor, or any AI agent operate real infrastructure —
without handing it a root shell.

[![CI](https://github.com/polymatx/opsgate/actions/workflows/ci.yml/badge.svg)](https://github.com/polymatx/opsgate/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/polymatx/opsgate)](https://goreportcard.com/report/github.com/polymatx/opsgate)
[![Go Reference](https://pkg.go.dev/badge/github.com/polymatx/opsgate.svg)](https://pkg.go.dev/github.com/polymatx/opsgate)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## The problem

Letting an AI agent run your servers today means giving it `exec("<any string>")` over SSH.
Existing SSH MCP servers do exactly that — some try to make it safe by blocking commands
that *look* dangerous with regex denylists.

That does not work. Denylists are guesswork against an adversary with infinite phrasings:

```
rm -rf /              →  blocked
r''m -rf /            →  not blocked
echo cm0gLXJmIC8K | base64 -d | sh   →  not blocked
```

And "dangerous" isn't even the hard part. `systemctl restart nginx` is a perfectly normal
command that is catastrophic at 3pm on Black Friday.

## The approach

opsgate does not filter strings. **It never gives the agent a string to fill in.**

The agent gets 25 typed tools — `service_restart(name)`, `docker_logs(container)`,
`journal_tail(unit, since, priority)` — and opsgate builds the command itself as an
`argv` array. There is no shell to inject into, because no shell string is ever assembled
from agent input.

On top of that, four layers:

| Layer | What it does |
|---|---|
| **Structured tools** | Commands are built as `argv`, never string-concatenated. Injection is impossible by construction, not by filtering. |
| **Deny-by-default policy** | Three modes — `observe` (read-only), `operate` (writes need approval), `full`. Per-host overrides, per-tool target allowlists. |
| **Human approval gates** | Mutating calls pause and ask you, showing the exact command. Requires a client that supports MCP elicitation; if it cannot ask, the call is refused rather than run. |
| **Tamper-evident audit** | Every call — including every refusal — appended to a hash-chained JSONL log. Editing or deleting any line is detectable. |

The default mode is `observe`. Out of the box, an agent can diagnose your servers
and change nothing.

## Quickstart

```bash
go install github.com/polymatx/opsgate/cmd/opsgate@latest
```

Create a config:

```bash
opsgate init
```

```yaml
# opsgate.yaml
mode: observe            # read-only until you say otherwise
default_host: local

hosts:
  web1:
    addr: 203.0.113.10
    user: root
    key: ~/.ssh/id_ed25519

files:
  allow_paths: [/var/log, /etc/nginx]
```

Register it with Claude Code:

```bash
claude mcp add opsgate -- opsgate serve --config /path/to/opsgate.yaml
```

Then ask your agent things like:

> Why is nginx throwing 502s on web1?

It will read `service_status`, `journal_tail`, and `docker_ps`, correlate them, and tell you.
In `observe` mode it *cannot* restart anything, no matter how it is prompted.

## Modes

```yaml
mode: observe   # read-only. Mutating tools are refused outright.
mode: operate   # reads run freely; every write asks you first.  ← recommended
mode: full      # writes run unprompted. Still fully audited.
```

Pin production tighter than everything else:

```yaml
mode: operate
hosts:
  prod:
    addr: 10.0.0.1
    mode: observe        # prod is read-only even though the default is operate
  staging:
    addr: 10.0.0.2       # inherits operate
```

Restrict *what* a tool may touch:

```yaml
tools:
  service_restart:
    allow_targets: ["nginx", "myapp*"]   # postgresql is not restartable, period
  service_stop:
    enabled: false                       # remove the tool entirely
  shell_exec:
    enabled: true                        # opt in to freeform shell (still approval-gated)
```

Setting `allow_targets` also makes the target **mandatory** for that tool: omitting it is
usually broader than any allowed value — `journal_tail` with no unit reads the whole
journal — so an unconstrained call is refused rather than silently permitted.

## Tools

**Observe** — always available

`system_info` · `disk_usage` · `process_top` · `listening_ports` · `service_list` ·
`service_status` · `docker_ps` · `docker_logs` · `docker_inspect` · `docker_stats` ·
`compose_ps` · `journal_tail` · `journal_errors` · `file_read` · `dir_list` ·
`file_grep` · `nginx_test`

**Mutate** — refused in `observe`, approval-gated in `operate`

`service_restart` · `service_start` · `service_stop` · `service_reload` ·
`docker_restart` · `docker_start` · `docker_stop` · `nginx_reload`

**Opt-in**

`shell_exec` — freeform shell. Disabled unless you enable it; always approval-gated.
It exists for the genuine long tail, and everything above exists so you rarely need it.

`nginx_reload` runs `nginx -t` first and refuses to reload a config that does not parse.

## The audit log

Every call appends one JSON line embedding the hash of the previous record:

```jsonl
{"seq":41,"time":"2026-07-29T11:02:14Z","host":"web1","tool":"service_status","decision":"allow","exit_code":0,...,"prev_hash":"9f2c…","hash":"41ab…"}
{"seq":42,"time":"2026-07-29T11:02:31Z","host":"web1","tool":"file_read","args":{"path":"/root/.ssh/id_rsa"},"decision":"deny","error":"outside the allowed paths",...}
{"seq":43,"time":"2026-07-29T11:03:02Z","host":"web1","tool":"service_restart","phase":"intent","decision":"needs_approval","approved":true,...}
{"seq":44,"time":"2026-07-29T11:03:02Z","host":"web1","tool":"service_restart","phase":"outcome","decision":"needs_approval","approved":true,"exit_code":0,...}
```

Refusals are recorded too — a blocked attempt to read a private key is exactly what you
want to find later.

A state-changing call writes two records: `phase: intent` **before** the command runs and
`phase: outcome` after. If the intent record cannot be written, opsgate refuses to act —
so an action that happened can never be missing from the log.

```bash
$ opsgate audit verify
audit chain OK: 143 records verified in ~/.opsgate/audit.jsonl
```

Remove or edit any line and verification fails at that point:

```bash
$ opsgate audit verify
opsgate: audit chain INVALID after 41 records: line 42: record tampered (hash mismatch)
```

Values under keys like `password` and `token` are redacted before they are written.

## Remote transport

For a shared or hosted setup, serve streamable HTTP instead of stdio:

```yaml
http:
  addr: "127.0.0.1:8080"
  auth_token: "a-long-random-token"     # required as: Authorization: Bearer <token>
```

```bash
opsgate serve --http 127.0.0.1:8080
```

Put it behind TLS if it leaves localhost.

## Security model

opsgate reduces blast radius. It is not a sandbox, and it does not make an untrusted
agent safe to point at production.

**What it guarantees**

- Agent input never becomes shell syntax. Commands are `argv`; the SSH transport
  single-quotes every element, so each argument stays one literal word.
- `observe` mode cannot mutate. There is no code path from a read-only mode to a
  state-changing command.
- File tools cannot escape `files.allow_paths` — paths are cleaned before the prefix
  check, so `/var/log/../../etc/shadow` is refused.
- SSH host keys are verified against `known_hosts`. Unknown keys are refused, never
  trusted on first use.
- Every decision is audited, including refusals.

**What it does not**

- Tools run with the privileges of your SSH user. If that is root, an approved call is
  a root call. Give opsgate its own least-privilege user.
- `shell_exec`, once enabled and approved, is arbitrary code execution. That is its purpose.
- `full` mode removes the human. Use it only where you accept that.
- A prompt-injected agent can still call *allowed* tools with plausible arguments. The
  policy is what bounds the damage — keep `allow_targets` tight.

See [docs/threat-model.md](docs/threat-model.md) for detail.

## Why this exists

I run my own infrastructure and I wanted to point Claude at it. Every existing option
asked me to choose between "useless" and "here is a root shell, good luck." opsgate is
the middle: the agent gets real capability, I keep the veto and the receipts.

## Contributing

Issues and PRs welcome — especially additional structured tools (k8s, PostgreSQL, MySQL,
Caddy) and policy primitives. New tools must be argv-built and classified `Observe` or
`Mutate`; anything needing a shell string belongs behind `shell_exec`.

```bash
go test ./...
go vet ./...
```

## License

MIT — see [LICENSE](LICENSE).
