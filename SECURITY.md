# Security policy

## Reporting a vulnerability

Please report security issues through
[GitHub security advisories](https://github.com/polymatx/opsgate/security/advisories/new)
rather than a public issue.

Include the version or commit, your configuration (with secrets removed), and the
sequence of tool calls that demonstrates the problem. If you have a proof of concept,
include it — a concrete bypass is far more useful than a description of one.

Expect an initial response within a few days.

## What counts as a vulnerability

These are in scope and treated as security bugs:

- **Argument injection** — any tool argument that causes a command other than the
  intended one to run, on either the local or SSH executor.
- **Policy bypass** — a mutating operation succeeding on a host in `observe` mode; a
  target outside `allow_targets` being acted on; a tool with `enabled: false` being
  callable.
- **Approval bypass** — a mutating call executing in `operate` mode without an accepted
  elicitation response, including through elicitation errors or client behaviour.
- **Path escape** — a file tool reading outside `files.allow_paths`.
- **Audit integrity** — a tool call that executes without producing a record, or a
  modification to the log that `opsgate audit verify` reports as valid.
- **Secret leakage** — credentials appearing in the audit log despite matching a
  `redact_keys` entry.
- **Transport** — accepting an unverified SSH host key, or the HTTP transport serving a
  request without a valid bearer token when `auth_token` is set.

## What does not count

These are documented properties, not bugs — see
[docs/threat-model.md](docs/threat-model.md):

- `shell_exec` running arbitrary commands once enabled and approved. That is the tool.
- `full` mode executing mutating tools without a prompt.
- Commands running with the privileges of the configured SSH user, including root if you
  configured root.
- An agent calling *permitted* tools with plausible arguments after prompt injection.
  Policy scope is the mitigation; `allow_targets` is how you narrow it.
- Rewriting the entire audit chain with filesystem write access. The chain is
  tamper-evident, not tamper-proof; ship the log off-box if that is your threat.
- Symlinks inside an allowed path pointing outside it. The path check is lexical; do not
  put untrusted-writable directories in `allow_paths`.

## Supported versions

The latest tagged release receives security fixes.
