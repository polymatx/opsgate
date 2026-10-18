# opsgate plugin for Claude Code

Lets Claude Code inspect and operate your servers through [opsgate](https://github.com/polymatx/opsgate) instead of a shell.

- **MCP server**: runs `opsgate serve`, which reads `~/.opsgate/config.yaml`. Without it, it is read-only on the local machine. It never reads a config from the project you have open.
- **Skill** `server-ops`: investigate with read-only tools first, change state only after a diagnosis, and treat refusals as final.
- **Command** `/opsgate:health-check [host]`: a read-only health report.

## Install

1. Install the binary: `go install github.com/polymatx/opsgate/cmd/opsgate@latest`, or download one from the [releases](https://github.com/polymatx/opsgate/releases).
2. In Claude Code:

   ```
   /plugin marketplace add polymatx/opsgate
   /plugin install opsgate@opsgate
   ```

3. Optional: `opsgate init` writes a starter config to `~/.opsgate/config.yaml` for your hosts and modes.
