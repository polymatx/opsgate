# Contributing to opsgate

Thanks for considering a contribution. opsgate is a security tool, so the bar for
changes is "does this preserve the guarantee," not just "does this work."

## The one rule

**Never build a command by concatenating agent-supplied input into a string.**

Commands are `[]string` argv. This is the property that makes injection impossible,
and it is easy to break by accident:

```go
// Correct — the name is one argv element, whatever it contains
argv := []string{"systemctl", "restart", in.Name}

// Wrong — never do this
argv := []string{"sh", "-c", "systemctl restart " + in.Name}
```

If a tool genuinely needs shell features (pipes, globbing), the shell string must be
a fixed literal with only validated, bounded values interpolated — see `process_top`,
where the sort key comes from a closed set and the limit is a clamped integer. If you
cannot do that, the operation belongs behind `shell_exec`.

## Adding a tool

1. **Classify it.** `policy.Observe` if it only reads, `policy.Mutate` if it changes
   anything. When in doubt, `Mutate` — a read-only tool misclassified as mutating is an
   annoyance; the reverse is a security hole.

2. **Register it with `add()`**, not `mcp.AddTool` directly, so `enabled: false` works.

3. **Route through `g.run()`** so policy, approval, and audit all apply. There is no
   legitimate reason for a tool to call an executor directly.

4. **Set `target`** to the primary object (service name, container, path). This is what
   `allow_targets` filters on and what gets charset-validated.

5. **Audit early refusals** with `g.refuse()` rather than `errResult()`, so a rejected
   attempt still lands in the log.

6. **Write a `summary`** for mutating tools. It is what the human reads when deciding
   whether to approve, so describe the consequence: "This will restart the service
   "nginx"", not "Running systemctl".

A minimal example:

```go
add(s, g, "service_reload", policy.Mutate, &mcp.Tool{
	Description: "Reload a systemd service's configuration without restarting it.",
}, func(ctx context.Context, req *mcp.CallToolRequest, in nameArgs) (*mcp.CallToolResult, any, error) {
	host := g.resolveHost(in.Host)
	res, err := g.run(ctx, req, call{
		tool:    "service_reload",
		class:   policy.Mutate,
		host:    host,
		target:  in.Name,
		argv:    []string{"systemctl", "reload", in.Name},
		args:    map[string]any{"host": host, "name": in.Name},
		summary: fmt.Sprintf("This will reload the service %q.", in.Name),
	})
	return res, nil, err
})
```

## Tests we expect

For a new tool, at minimum:

- it is refused in `observe` mode if it mutates, **and the executor is never called**
  (see `TestGateBlocksMutationInObserveModeWithoutRunningAnything`)
- an injection-shaped argument is refused before execution
- `allow_targets` restricts it as documented

For anything touching paths, add cases to `files_test.go` proving traversal is rejected.

```bash
go test -race ./...
go vet ./...
gofmt -l .          # must print nothing
```

## What we are looking for

**Wanted:** more structured tools — Kubernetes, PostgreSQL, MySQL, Caddy, Traefik,
ufw/iptables status, certificate expiry. Policy primitives: time windows, rate limits,
per-tool concurrency caps. Audit sinks: syslog, S3 append-only, webhook.

**Not wanted:** a generic "run any command" tool by another name. Anything that makes
`observe` mode capable of mutation. Regex-based command denylisting — that is the
approach opsgate exists to replace.

## Reporting a vulnerability

Open a GitHub security advisory rather than a public issue.
