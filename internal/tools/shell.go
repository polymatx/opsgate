package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/polymatx/opsgate/internal/policy"
)

// registerShell adds the freeform escape hatch. It is disabled unless the
// operator sets tools.shell_exec.enabled: true, and it always requires
// approval unless the host is in full mode with approval: never.
//
// Everything else in opsgate is a structured tool precisely so that this one
// does not have to exist; it is here for the genuine long tail.
func registerShell(s *mcp.Server, g *Gate) {
	type shellArgs struct {
		hostArg
		Command string `json:"command" jsonschema:"the shell command to run; shown verbatim to the human for approval"`
		Reason  string `json:"reason" jsonschema:"why this command is needed - shown to the human in the approval prompt"`
	}
	add(s, g, "shell_exec", policy.Shell, &mcp.Tool{
		Description: "Run an arbitrary shell command. Disabled by default; requires human approval when enabled. " +
			"Prefer the structured tools — use this only when no structured tool fits.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in shellArgs) (*mcp.CallToolResult, any, error) {
		host := g.resolveHost(in.Host)
		if in.Command == "" {
			return g.refuse(host, "shell_exec", map[string]any{"host": host},
				"Refused: command must not be empty."), nil, nil
		}
		summary := "FREEFORM SHELL COMMAND — read it carefully before approving."
		if in.Reason != "" {
			summary = "Reason given by the agent: " + in.Reason + "\n\n" + summary
		}
		res, err := g.run(ctx, req, call{
			tool:  "shell_exec",
			class: policy.Shell,
			host:  host,
			// The command is deliberately handed to a shell — that is the point of
			// this tool. Safety comes from it being opt-in plus approval-gated,
			// not from filtering the string.
			argv:    []string{"sh", "-c", in.Command},
			args:    map[string]any{"host": host, "command": in.Command, "reason": in.Reason},
			summary: summary,
		})
		return res, nil, err
	})
}
