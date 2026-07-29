package tools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/polymatx/opsgate/internal/policy"
)

func registerDocker(s *mcp.Server, g *Gate) {
	type psArgs struct {
		hostArg
		All bool `json:"all,omitempty" jsonschema:"include stopped containers (default false)"`
	}
	add(s, g, "docker_ps", policy.Observe, &mcp.Tool{
		Description: "List Docker containers with status, image and ports.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in psArgs) (*mcp.CallToolResult, any, error) {
		host := g.resolveHost(in.Host)
		argv := []string{"docker", "ps", "--format",
			"table {{.Names}}\t{{.Status}}\t{{.Image}}\t{{.Ports}}"}
		if in.All {
			argv = append(argv, "--all")
		}
		res, err := g.run(ctx, req, call{
			tool:  "docker_ps",
			class: policy.Observe,
			host:  host,
			argv:  argv,
			args:  map[string]any{"host": host, "all": in.All},
		})
		return res, nil, err
	})

	type logArgs struct {
		hostArg
		Container string `json:"container" jsonschema:"container name or ID"`
		Lines     int    `json:"lines,omitempty" jsonschema:"how many trailing log lines (default 100, max 2000)"`
	}
	add(s, g, "docker_logs", policy.Observe, &mcp.Tool{
		Description: "Read the recent logs of a Docker container.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in logArgs) (*mcp.CallToolResult, any, error) {
		host := g.resolveHost(in.Host)
		lines := clamp(in.Lines, 100, 2000)
		res, err := g.run(ctx, req, call{
			tool:   "docker_logs",
			class:  policy.Observe,
			host:   host,
			target: in.Container,
			argv:   []string{"docker", "logs", "--tail", fmt.Sprint(lines), in.Container},
			args:   map[string]any{"host": host, "container": in.Container, "lines": lines},
		})
		return res, nil, err
	})

	type inspectArgs struct {
		hostArg
		Container string `json:"container" jsonschema:"container name or ID"`
	}
	add(s, g, "docker_inspect", policy.Observe, &mcp.Tool{
		Description: "Inspect a container's health, restart count, image and mounts.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in inspectArgs) (*mcp.CallToolResult, any, error) {
		host := g.resolveHost(in.Host)
		res, err := g.run(ctx, req, call{
			tool:   "docker_inspect",
			class:  policy.Observe,
			host:   host,
			target: in.Container,
			argv: []string{"docker", "inspect", "--format",
				"name={{.Name}}\nstate={{.State.Status}}\nhealth={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}\n" +
					"restarts={{.RestartCount}}\nimage={{.Config.Image}}\nstarted={{.State.StartedAt}}\nmounts={{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}",
				in.Container},
			args: map[string]any{"host": host, "container": in.Container},
		})
		return res, nil, err
	})

	add(s, g, "docker_stats", policy.Observe, &mcp.Tool{
		Description: "Show a one-shot snapshot of container CPU and memory usage.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in emptyHostArgs) (*mcp.CallToolResult, any, error) {
		host := g.resolveHost(in.Host)
		res, err := g.run(ctx, req, call{
			tool:  "docker_stats",
			class: policy.Observe,
			host:  host,
			argv: []string{"docker", "stats", "--no-stream", "--format",
				"table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}"},
			args: map[string]any{"host": host},
		})
		return res, nil, err
	})

	type ctrArgs struct {
		hostArg
		Container string `json:"container" jsonschema:"container name or ID"`
	}
	for _, action := range []struct {
		tool, verb, desc string
	}{
		{"docker_restart", "restart", "Restart a Docker container."},
		{"docker_start", "start", "Start a stopped Docker container."},
		{"docker_stop", "stop", "Stop a running Docker container."},
	} {
		action := action
		add(s, g, action.tool, policy.Mutate, &mcp.Tool{
			Description: action.desc,
		}, func(ctx context.Context, req *mcp.CallToolRequest, in ctrArgs) (*mcp.CallToolResult, any, error) {
			host := g.resolveHost(in.Host)
			res, err := g.run(ctx, req, call{
				tool:    action.tool,
				class:   policy.Mutate,
				host:    host,
				target:  in.Container,
				argv:    []string{"docker", action.verb, in.Container},
				args:    map[string]any{"host": host, "container": in.Container},
				summary: fmt.Sprintf("This will %s the container %q.", action.verb, in.Container),
			})
			return res, nil, err
		})
	}

	type composeArgs struct {
		hostArg
		Dir string `json:"dir" jsonschema:"directory containing the compose file"`
	}
	add(s, g, "compose_ps", policy.Observe, &mcp.Tool{
		Description: "List services of a Docker Compose project in a directory.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in composeArgs) (*mcp.CallToolResult, any, error) {
		host := g.resolveHost(in.Host)
		res, err := g.run(ctx, req, call{
			tool:   "compose_ps",
			class:  policy.Observe,
			host:   host,
			target: in.Dir,
			argv:   []string{"docker", "compose", "--project-directory", in.Dir, "ps"},
			args:   map[string]any{"host": host, "dir": in.Dir},
		})
		return res, nil, err
	})
}

func clamp(v, def, max int) int {
	if v <= 0 {
		return def
	}
	if v > max {
		return max
	}
	return v
}
