---
description: Read-only health check of a host through opsgate (load, memory, disk, failed services, recent errors, containers, open ports)
argument-hint: "[host]"
---

Run a read-only health check of host `$ARGUMENTS` with the opsgate tools. If no host was given, use opsgate's default host. Call only tools that read; change nothing.

1. `system_info`: uptime, load and memory.
2. `disk_usage`: flag any filesystem above 85%.
3. `service_list` with state `failed`.
4. `journal_errors`: recent errors, grouped by unit.
5. `docker_ps`: containers that are not running or not healthy. Skip this if Docker is not installed.
6. `listening_ports`: note anything bound to all interfaces that looks unexpected.

Report a one-line verdict (healthy, or needs attention), then each finding with its evidence and the tool that showed it. Suggest fixes but do not apply them; if the user asks for one, follow the server-ops skill.
