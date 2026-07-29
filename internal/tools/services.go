package tools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/polymatx/opsgate/internal/policy"
)

func registerServices(s *mcp.Server, g *Gate) {
	type listArgs struct {
		hostArg
		State string `json:"state,omitempty" jsonschema:"filter by state: running, failed, or all (default running)"`
	}
	add(s, g, "service_list", policy.Observe, &mcp.Tool{
		Description: "List systemd services on a host, optionally filtered to running or failed units.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in listArgs) (*mcp.CallToolResult, any, error) {
		host := g.resolveHost(in.Host)
		argv := []string{"systemctl", "list-units", "--type=service", "--no-pager", "--no-legend"}
		switch in.State {
		case "", "running":
			argv = append(argv, "--state=running")
		case "failed":
			argv = append(argv, "--state=failed")
		case "all":
			argv = append(argv, "--all")
		default:
			return g.refuse(host, "service_list", map[string]any{"host": host, "state": in.State},
				fmt.Sprintf("Unknown state %q; use running, failed, or all.", in.State)), nil, nil
		}
		res, err := g.run(ctx, req, call{
			tool:  "service_list",
			class: policy.Observe,
			host:  host,
			argv:  argv,
			args:  map[string]any{"host": host, "state": in.State},
		})
		return res, nil, err
	})

	type nameArgs struct {
		hostArg
		Name string `json:"name" jsonschema:"systemd unit name, for example nginx or docker.service"`
	}

	add(s, g, "service_status", policy.Observe, &mcp.Tool{
		Description: "Show the status of one systemd service, including recent log lines.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in nameArgs) (*mcp.CallToolResult, any, error) {
		host := g.resolveHost(in.Host)
		res, err := g.run(ctx, req, call{
			tool:   "service_status",
			class:  policy.Observe,
			host:   host,
			target: in.Name,
			argv:   []string{"systemctl", "status", in.Name, "--no-pager", "--lines=20"},
			args:   map[string]any{"host": host, "name": in.Name},
		})
		return res, nil, err
	})

	// Mutating service actions. Each is a separate tool so that policy and the
	// approval prompt name exactly one verb — there is no generic
	// "run systemctl <anything>" escape hatch.
	for _, action := range []struct {
		tool, verb, desc string
	}{
		{"service_restart", "restart", "Restart a systemd service."},
		{"service_start", "start", "Start a stopped systemd service."},
		{"service_stop", "stop", "Stop a running systemd service."},
		{"service_reload", "reload", "Reload a systemd service's configuration without restarting it."},
	} {
		action := action
		add(s, g, action.tool, policy.Mutate, &mcp.Tool{
			Description: action.desc,
		}, func(ctx context.Context, req *mcp.CallToolRequest, in nameArgs) (*mcp.CallToolResult, any, error) {
			host := g.resolveHost(in.Host)
			res, err := g.run(ctx, req, call{
				tool:    action.tool,
				class:   policy.Mutate,
				host:    host,
				target:  in.Name,
				argv:    []string{"systemctl", action.verb, in.Name},
				args:    map[string]any{"host": host, "name": in.Name},
				summary: fmt.Sprintf("This will %s the service %q.", action.verb, in.Name),
			})
			return res, nil, err
		})
	}
}
