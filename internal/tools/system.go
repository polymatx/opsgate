package tools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/polymatx/opsgate/internal/policy"
)

type emptyHostArgs struct {
	hostArg
}

func registerSystem(s *mcp.Server, g *Gate) {
	add(s, g, "system_info", policy.Observe, &mcp.Tool{
		Description: "Show kernel, uptime, load average and memory usage for a host.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in emptyHostArgs) (*mcp.CallToolResult, any, error) {
		host := g.resolveHost(in.Host)
		res, err := g.run(ctx, req, call{
			tool:  "system_info",
			class: policy.Observe,
			host:  host,
			argv:  []string{"sh", "-c", "uname -a; echo; uptime; echo; free -h 2>/dev/null || vm_stat"},
			args:  map[string]any{"host": host},
		})
		return res, nil, err
	})

	add(s, g, "disk_usage", policy.Observe, &mcp.Tool{
		Description: "Show mounted filesystem usage (df -h) for a host.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in emptyHostArgs) (*mcp.CallToolResult, any, error) {
		host := g.resolveHost(in.Host)
		res, err := g.run(ctx, req, call{
			tool:  "disk_usage",
			class: policy.Observe,
			host:  host,
			argv:  []string{"df", "-h"},
			args:  map[string]any{"host": host},
		})
		return res, nil, err
	})

	type topArgs struct {
		hostArg
		By    string `json:"by,omitempty" jsonschema:"sort processes by cpu or mem (default cpu)"`
		Limit int    `json:"limit,omitempty" jsonschema:"how many processes to return (default 15, max 50)"`
	}
	add(s, g, "process_top", policy.Observe, &mcp.Tool{
		Description: "List the top processes on a host by CPU or memory usage.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in topArgs) (*mcp.CallToolResult, any, error) {
		host := g.resolveHost(in.Host)
		sortKey := "-pcpu"
		if in.By == "mem" {
			sortKey = "-pmem"
		}
		limit := in.Limit
		if limit <= 0 {
			limit = 15
		}
		if limit > 50 {
			limit = 50
		}
		res, err := g.run(ctx, req, call{
			tool:  "process_top",
			class: policy.Observe,
			host:  host,
			// ps writes all rows; head bounds the output. Both are fixed argv
			// elements — only validated numbers/keys vary.
			argv: []string{"sh", "-c", fmt.Sprintf("ps -eo pid,user,pcpu,pmem,etime,comm --sort=%s | head -n %d", sortKey, limit+1)},
			args: map[string]any{"host": host, "by": in.By, "limit": limit},
		})
		return res, nil, err
	})

	add(s, g, "listening_ports", policy.Observe, &mcp.Tool{
		Description: "List listening TCP/UDP sockets and the processes owning them.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in emptyHostArgs) (*mcp.CallToolResult, any, error) {
		host := g.resolveHost(in.Host)
		res, err := g.run(ctx, req, call{
			tool:  "listening_ports",
			class: policy.Observe,
			host:  host,
			argv:  []string{"sh", "-c", "ss -tulpn 2>/dev/null || netstat -an | grep -i listen"},
			args:  map[string]any{"host": host},
		})
		return res, nil, err
	})
}
