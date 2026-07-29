package tools

import (
	"context"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/polymatx/opsgate/internal/policy"
)

func registerFiles(s *mcp.Server, g *Gate) {
	type readArgs struct {
		hostArg
		Path  string `json:"path" jsonschema:"absolute path of the file to read"`
		Lines int    `json:"lines,omitempty" jsonschema:"read only the last N lines instead of the whole file"`
	}
	add(s, g, "file_read", policy.Observe, &mcp.Tool{
		Description: "Read a file under one of the configured allowed paths (see files.allow_paths).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in readArgs) (*mcp.CallToolResult, any, error) {
		host := g.resolveHost(in.Host)
		clean, ok := g.allowedPath(in.Path)
		if !ok {
			return g.refuse(host, "file_read", map[string]any{"host": host, "path": in.Path},
				g.pathRefusal(in.Path)), nil, nil
		}
		argv := []string{"cat", clean}
		if in.Lines > 0 {
			argv = []string{"tail", "-n", fmt.Sprint(clamp(in.Lines, 100, 5000)), clean}
		}
		res, err := g.run(ctx, req, call{
			tool:   "file_read",
			class:  policy.Observe,
			host:   host,
			target: clean,
			argv:   argv,
			args:   map[string]any{"host": host, "path": clean, "lines": in.Lines},
		})
		return res, nil, err
	})

	type listArgs struct {
		hostArg
		Path string `json:"path" jsonschema:"absolute directory path to list"`
	}
	add(s, g, "dir_list", policy.Observe, &mcp.Tool{
		Description: "List a directory under one of the configured allowed paths.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in listArgs) (*mcp.CallToolResult, any, error) {
		host := g.resolveHost(in.Host)
		clean, ok := g.allowedPath(in.Path)
		if !ok {
			return g.refuse(host, "dir_list", map[string]any{"host": host, "path": in.Path},
				g.pathRefusal(in.Path)), nil, nil
		}
		res, err := g.run(ctx, req, call{
			tool:   "dir_list",
			class:  policy.Observe,
			host:   host,
			target: clean,
			argv:   []string{"ls", "-lah", "--", clean},
			args:   map[string]any{"host": host, "path": clean},
		})
		return res, nil, err
	})

	type grepArgs struct {
		hostArg
		Path    string `json:"path" jsonschema:"absolute file path to search"`
		Pattern string `json:"pattern" jsonschema:"fixed string to search for (not a regular expression)"`
		Lines   int    `json:"lines,omitempty" jsonschema:"maximum matching lines to return (default 100, max 1000)"`
	}
	add(s, g, "file_grep", policy.Observe, &mcp.Tool{
		Description: "Search a file for a fixed string. Useful for finding an error in a large log.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in grepArgs) (*mcp.CallToolResult, any, error) {
		host := g.resolveHost(in.Host)
		clean, ok := g.allowedPath(in.Path)
		if !ok {
			return g.refuse(host, "file_grep", map[string]any{"host": host, "path": in.Path},
				g.pathRefusal(in.Path)), nil, nil
		}
		if in.Pattern == "" || len(in.Pattern) > 256 {
			return g.refuse(host, "file_grep", map[string]any{"host": host, "path": clean},
				"Refused: pattern must be between 1 and 256 characters."), nil, nil
		}
		max := clamp(in.Lines, 100, 1000)
		// -F: fixed string, so the pattern is never interpreted as a regex.
		// -m: bound the match count. The pattern travels as its own argv element.
		res, err := g.run(ctx, req, call{
			tool:   "file_grep",
			class:  policy.Observe,
			host:   host,
			target: clean,
			argv:   []string{"grep", "-F", "-n", "-m", fmt.Sprint(max), "--", in.Pattern, clean},
			args:   map[string]any{"host": host, "path": clean, "pattern": in.Pattern, "lines": max},
		})
		return res, nil, err
	})

	registerNginx(s, g)
}

func registerNginx(s *mcp.Server, g *Gate) {
	add(s, g, "nginx_test", policy.Observe, &mcp.Tool{
		Description: "Validate the nginx configuration (nginx -t) without applying it.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in emptyHostArgs) (*mcp.CallToolResult, any, error) {
		host := g.resolveHost(in.Host)
		res, err := g.run(ctx, req, call{
			tool:  "nginx_test",
			class: policy.Observe,
			host:  host,
			argv:  []string{"nginx", "-t"},
			args:  map[string]any{"host": host},
		})
		return res, nil, err
	})

	add(s, g, "nginx_reload", policy.Mutate, &mcp.Tool{
		Description: "Reload nginx. Validates the configuration first and refuses to reload a broken config.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in emptyHostArgs) (*mcp.CallToolResult, any, error) {
		host := g.resolveHost(in.Host)
		// Guard rail: never reload a config that does not parse.
		check, err := g.run(ctx, req, call{
			tool:  "nginx_test",
			class: policy.Observe,
			host:  host,
			argv:  []string{"nginx", "-t"},
			args:  map[string]any{"host": host, "phase": "preflight"},
		})
		if err != nil {
			return nil, nil, err
		}
		if check.IsError {
			return errResult("Refused to reload: nginx -t failed.\n\n" + textOf(check)), nil, nil
		}
		res, err := g.run(ctx, req, call{
			tool:    "nginx_reload",
			class:   policy.Mutate,
			host:    host,
			argv:    []string{"nginx", "-s", "reload"},
			args:    map[string]any{"host": host},
			summary: "The nginx configuration passed validation. This will reload nginx.",
		})
		return res, nil, err
	})
}

// allowedPath cleans p and checks it against files.allow_paths. It returns the
// cleaned absolute path. Symlink escapes are handled on the host side by using
// the cleaned path only; traversal like /var/log/../../etc/shadow is rejected
// because cleaning resolves it before the prefix check.
func (g *Gate) allowedPath(p string) (string, bool) {
	if p == "" || !strings.HasPrefix(p, "/") {
		return "", false
	}
	clean := path.Clean(p)
	if strings.Contains(clean, "\x00") {
		return "", false
	}
	for _, allowed := range g.cfg.Files.AllowPaths {
		a := path.Clean(allowed)
		if clean == a {
			return clean, true
		}
		if strings.HasPrefix(clean, a+"/") {
			return clean, true
		}
		// Support explicit glob entries such as /srv/*/logs.
		if ok, err := filepath.Match(a, clean); err == nil && ok {
			return clean, true
		}
	}
	return "", false
}

func (g *Gate) pathRefusal(p string) string {
	return fmt.Sprintf(
		"Refused: %q is outside the allowed paths. opsgate only exposes: %s (configure files.allow_paths to change this).",
		p, strings.Join(g.cfg.Files.AllowPaths, ", "))
}

func textOf(r *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range r.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			b.WriteString(t.Text)
		}
	}
	return b.String()
}
