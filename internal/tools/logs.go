package tools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/polymatx/opsgate/internal/policy"
)

func registerLogs(s *mcp.Server, g *Gate) {
	type journalArgs struct {
		hostArg
		Unit     string `json:"unit,omitempty" jsonschema:"systemd unit to filter by; omit for the whole journal"`
		Lines    int    `json:"lines,omitempty" jsonschema:"how many trailing lines (default 100, max 2000)"`
		Since    string `json:"since,omitempty" jsonschema:"systemd time expression such as '1 hour ago' or '2026-07-29 10:00'"`
		Priority string `json:"priority,omitempty" jsonschema:"minimum priority: emerg, alert, crit, err, warning, notice, info, debug"`
	}
	add(s, g, "journal_tail", policy.Observe, &mcp.Tool{
		Description: "Read recent systemd journal entries, optionally filtered by unit, time and priority.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in journalArgs) (*mcp.CallToolResult, any, error) {
		host := g.resolveHost(in.Host)
		lines := clamp(in.Lines, 100, 2000)
		argv := []string{"journalctl", "--no-pager", "-n", fmt.Sprint(lines)}
		auditArgs := map[string]any{
			"host": host, "unit": in.Unit, "since": in.Since, "priority": in.Priority,
		}
		if in.Unit != "" {
			if !policy.ValidTarget(in.Unit) {
				return g.refuse(host, "journal_tail", auditArgs,
					fmt.Sprintf("Refused: %q is not a valid unit name.", in.Unit)), nil, nil
			}
			argv = append(argv, "-u", in.Unit)
		}
		if in.Since != "" {
			if !validTimeExpr(in.Since) {
				return g.refuse(host, "journal_tail", auditArgs,
					fmt.Sprintf("Refused: %q is not an accepted time expression.", in.Since)), nil, nil
			}
			argv = append(argv, "--since", in.Since)
		}
		if in.Priority != "" {
			if !validPriority(in.Priority) {
				return g.refuse(host, "journal_tail", auditArgs,
					fmt.Sprintf("Refused: %q is not a valid priority.", in.Priority)), nil, nil
			}
			argv = append(argv, "-p", in.Priority)
		}
		res, err := g.run(ctx, req, call{
			tool:   "journal_tail",
			class:  policy.Observe,
			host:   host,
			target: in.Unit,
			argv:   argv,
			args: map[string]any{
				"host": host, "unit": in.Unit, "lines": lines,
				"since": in.Since, "priority": in.Priority,
			},
		})
		return res, nil, err
	})

	type failedArgs struct {
		hostArg
	}
	add(s, g, "journal_errors", policy.Observe, &mcp.Tool{
		Description: "Show recent error-and-worse journal entries across the system — a fast triage starting point.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in failedArgs) (*mcp.CallToolResult, any, error) {
		host := g.resolveHost(in.Host)
		res, err := g.run(ctx, req, call{
			tool:  "journal_errors",
			class: policy.Observe,
			host:  host,
			argv:  []string{"journalctl", "--no-pager", "-p", "err", "-n", "200", "--since", "24 hours ago"},
			args:  map[string]any{"host": host},
		})
		return res, nil, err
	})
}

// validPriority guards the -p flag.
func validPriority(p string) bool {
	switch p {
	case "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug":
		return true
	}
	return false
}

// validTimeExpr allows only the characters used by systemd time expressions.
func validTimeExpr(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == ' ', r == '-', r == ':', r == '.', r == '+':
		default:
			return false
		}
	}
	return true
}
