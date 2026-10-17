---
name: server-ops
description: Use when the user asks to check, diagnose or change something on a server or on this machine (services, failed units, logs, disk space, memory, ports, processes, Docker containers, nginx) and the opsgate MCP tools are available. Covers how to investigate with read-only tools, when and how to change state, and what to do with approvals and refusals.
---

# Operating servers through opsgate

opsgate gives you typed tools instead of a shell. Each tool builds its own command from your arguments, the operator's policy decides what may run, and every call, refused ones included, goes into a hash-chained audit log. Work with that design, not around it.

## Before you start

- The opsgate server's instructions state the mode and the hosts. `observe` is read-only, `operate` asks the human before every change, `full` runs changes unprompted (still audited). Hosts can override the default mode.
- Pass `host` explicitly when there is more than one. `local` is the machine opsgate runs on.
- If no opsgate tools are available, the server is not running. Tell the user to install it (`go install github.com/polymatx/opsgate/cmd/opsgate@latest`, or a binary from https://github.com/polymatx/opsgate/releases) and check `/mcp`. Without a config file it starts read-only on the local machine; hosts and modes go in `./opsgate.yaml` or `~/.opsgate/config.yaml` (`opsgate init` writes a starter file).

## Investigate first

Use the narrowest tool that answers the question:

| Question | Tools |
|---|---|
| Is the machine healthy? | `system_info`, `disk_usage`, `process_top` |
| Is a service up, and why did it fail? | `service_status`, `journal_tail` for that unit, `journal_errors` |
| What failed recently? | `service_list` with state `failed`, `journal_errors` |
| What is listening on a port? | `listening_ports`, then `service_list` or `docker_ps` to find the owner |
| A container misbehaves | `docker_ps`, `docker_inspect` (health, restart count), `docker_logs`, `docker_stats`, `compose_ps` |
| The disk is filling up | `disk_usage`, then `dir_list` under the allowed paths |
| An error in a log file | `file_grep` (a fixed string, not a regex), `file_read` |
| An nginx config change | `nginx_test` |

State the diagnosis with its evidence (the log line, the status, the number) before proposing any change.

## Changing state

- Change things only after a diagnosis, and say in one line what you will change, on which host, and why.
- Use the specific tool: `service_reload`, `service_restart`, `service_start`, `service_stop`, `docker_restart`, `docker_start`, `docker_stop`, `nginx_reload` (it runs `nginx -t` first and refuses a config that does not parse). Prefer a reload to a restart when the service supports it.
- In `operate` mode the human sees an approval prompt with the exact command. If they deny it, stop: report what you would have done and do not try again.
- After a change, verify it (`service_status`, `docker_ps`, a short `journal_tail`) and report the result.

## Refusals are final

A refusal means the policy said no: the mode, `allow_targets`, `files.allow_paths`, or a disabled tool. Do not retry with another tool, another spelling of the path, or `shell_exec`. Tell the user which setting blocks the call (for example the host's `mode`, `tools.<tool>.allow_targets` or `files.allow_paths`) and leave the decision to them.

## shell_exec

It is not registered unless the operator enabled it, and it always needs approval. Use it only when no typed tool covers the task, and say why.

## Reporting

Finish with what you checked (tool and host), what you found, and what you changed, if anything. Every call is in the audit log; `opsgate audit verify` checks its hash chain.
