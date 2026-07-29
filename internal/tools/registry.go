// Package tools defines opsgate's structured MCP tools and the gate every
// call passes through: policy check -> human approval -> execute -> audit.
package tools

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/polymatx/opsgate/internal/audit"
	"github.com/polymatx/opsgate/internal/config"
	"github.com/polymatx/opsgate/internal/executor"
	"github.com/polymatx/opsgate/internal/policy"
)

// Gate owns the shared state every tool needs.
type Gate struct {
	cfg    *config.Config
	pol    *policy.Engine
	log    *audit.Logger
	mu     sync.Mutex
	execs  map[string]executor.Executor
	dialer func(name string, h config.Host, timeout time.Duration) (executor.Executor, error)
}

// NewGate builds a Gate. Executors are created lazily on first use per host.
func NewGate(cfg *config.Config, log *audit.Logger) *Gate {
	return &Gate{
		cfg:   cfg,
		pol:   policy.New(cfg),
		log:   log,
		execs: map[string]executor.Executor{},
		dialer: func(name string, h config.Host, timeout time.Duration) (executor.Executor, error) {
			return executor.DialSSH(name, h.Addr, h.User, h.Key, h.Port, timeout)
		},
	}
}

// Close releases every open executor.
func (g *Gate) Close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, e := range g.execs {
		_ = e.Close()
	}
	g.execs = map[string]executor.Executor{}
}

// Config exposes the loaded config (used by cmd for banners).
func (g *Gate) Config() *config.Config { return g.cfg }

// executorFor returns (creating if needed) the executor for a host name.
func (g *Gate) executorFor(host string) (executor.Executor, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if e, ok := g.execs[host]; ok {
		return e, nil
	}
	if host == "local" {
		e := executor.Local{}
		g.execs[host] = e
		return e, nil
	}
	h, ok := g.cfg.Hosts[host]
	if !ok {
		return nil, fmt.Errorf("unknown host %q; configured hosts: %s", host, strings.Join(g.hostNames(), ", "))
	}
	e, err := g.dialer(host, h, time.Duration(g.cfg.TimeoutSeconds)*time.Second)
	if err != nil {
		return nil, err
	}
	g.execs[host] = e
	return e, nil
}

func (g *Gate) hostNames() []string {
	names := []string{"local"}
	for n := range g.cfg.Hosts {
		names = append(names, n)
	}
	return names
}

// resolveHost picks the host for a call: explicit arg, else default.
func (g *Gate) resolveHost(arg string) string {
	if arg != "" {
		return arg
	}
	return g.cfg.DefaultHost
}

// call is one gated tool invocation.
type call struct {
	tool string
	// class determines policy treatment.
	class policy.Class
	// host is the resolved target host.
	host string
	// target is the primary object (service name, container, path). May be empty.
	target string
	// argv is the command to run.
	argv []string
	// args is recorded in the audit log.
	args map[string]any
	// summary is shown to the human in the approval prompt.
	summary string
}

// run executes a gated call and returns text output for the model.
func (g *Gate) run(ctx context.Context, req *mcp.CallToolRequest, c call) (*mcp.CallToolResult, error) {
	rec := audit.Record{
		Time: time.Now(),
		Host: c.host,
		Tool: c.tool,
		Args: c.args,
	}

	// Defense in depth: reject unusual target strings even though argv is never
	// interpolated into a shell.
	if c.target != "" && !policy.ValidTarget(c.target) {
		rec.Decision = "deny"
		rec.Err = "invalid target"
		g.logRec(rec)
		return errResult(fmt.Sprintf("Refused: %q contains characters that are not allowed in a target name.", c.target)), nil
	}

	decision, reason := g.pol.Check(c.host, c.tool, c.class, c.target)
	rec.Decision = decision.String()

	if decision == policy.Deny {
		rec.Err = reason
		g.logRec(rec)
		return errResult(fmt.Sprintf("Refused by opsgate policy: %s", reason)), nil
	}

	if decision == policy.NeedsApproval {
		approved, err := g.askApproval(ctx, req, c)
		rec.Approved = &approved
		if err != nil {
			rec.Err = err.Error()
			g.logRec(rec)
			return errResult(fmt.Sprintf(
				"Approval could not be requested (%v). This client may not support elicitation; "+
					"set tools.%s.approval: never or mode: full to allow it without prompting.", err, c.tool)), nil
		}
		if !approved {
			g.logRec(rec)
			return errResult("Denied by the human operator."), nil
		}
	}

	e, err := g.executorFor(c.host)
	if err != nil {
		rec.Err = err.Error()
		g.logRec(rec)
		return errResult(fmt.Sprintf("Cannot reach host %q: %v", c.host, err)), nil
	}

	runCtx, cancel := context.WithTimeout(ctx, time.Duration(g.cfg.TimeoutSeconds)*time.Second)
	defer cancel()

	res, runErr := e.Run(runCtx, c.argv)
	rec.ExitCode = res.ExitCode
	rec.DurationMS = res.Duration.Milliseconds()

	out := combineOutput(res)
	rec.OutputLen = len(out)
	rec.OutputSHA = audit.SumOutput([]byte(out))

	if runErr != nil {
		rec.Err = runErr.Error()
		g.logRec(rec)
		if errors.Is(runErr, context.DeadlineExceeded) {
			return errResult(fmt.Sprintf("Command timed out after %ds on %s.", g.cfg.TimeoutSeconds, c.host)), nil
		}
		return errResult(fmt.Sprintf("Command failed on %s: %v", c.host, runErr)), nil
	}
	g.logRec(rec)

	text := truncate(out, g.cfg.MaxOutputBytes)
	if strings.TrimSpace(text) == "" {
		text = fmt.Sprintf("(no output; exit code %d)", res.ExitCode)
	}
	if res.ExitCode != 0 {
		text = fmt.Sprintf("exit code %d\n%s", res.ExitCode, text)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
		IsError: res.ExitCode != 0,
	}, nil
}

// askApproval asks the human to confirm via MCP elicitation.
func (g *Gate) askApproval(ctx context.Context, req *mcp.CallToolRequest, c call) (bool, error) {
	if req == nil || req.Session == nil {
		return false, errors.New("no session available for elicitation")
	}
	msg := fmt.Sprintf("opsgate: allow %s on host %q?\n\n%s\n\nCommand: %s",
		c.tool, c.host, c.summary, executor.QuoteArgv(c.argv))

	res, err := req.Session.Elicit(ctx, &mcp.ElicitParams{
		Mode:    "confirmation",
		Message: msg,
	})
	if err != nil {
		return false, err
	}
	return res.Action == "accept", nil
}

func combineOutput(r executor.Result) string {
	var b strings.Builder
	b.WriteString(r.Stdout)
	if s := strings.TrimSpace(r.Stderr); s != "" {
		if b.Len() > 0 && !strings.HasSuffix(r.Stdout, "\n") {
			b.WriteString("\n")
		}
		b.WriteString("[stderr] ")
		b.WriteString(r.Stderr)
	}
	return b.String()
}

func truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + fmt.Sprintf("\n… [truncated, %d bytes total]", len(s))
}

func errResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}
}

// logRec writes an audit record, tolerating a nil logger (used in tests).
func (g *Gate) logRec(r audit.Record) {
	if g.log != nil {
		_ = g.log.Log(r)
	}
}

// refuse records a denial that is decided before any command is built —
// bad paths, malformed arguments — and returns the message for the model.
// Refusals must be audited: a blocked attempt to read /root/.ssh/id_rsa is
// exactly the event an operator needs to see afterwards.
func (g *Gate) refuse(host, tool string, args map[string]any, msg string) *mcp.CallToolResult {
	if g.log != nil {
		_ = g.log.Log(audit.Record{
			Time:     time.Now(),
			Host:     host,
			Tool:     tool,
			Args:     args,
			Decision: "deny",
			Err:      msg,
		})
	}
	return errResult(msg)
}

// hostArg is embedded in every tool's input struct.
type hostArg struct {
	Host string `json:"host,omitempty" jsonschema:"target host name from the opsgate config; omit for the default host"`
}

// Register adds every enabled tool to the server.
func Register(s *mcp.Server, g *Gate) {
	registerSystem(s, g)
	registerServices(s, g)
	registerDocker(s, g)
	registerLogs(s, g)
	registerFiles(s, g)
	registerShell(s, g)
}

// add registers a tool only when policy leaves it enabled.
func add[In, Out any](s *mcp.Server, g *Gate, name string, class policy.Class, t *mcp.Tool, h mcp.ToolHandlerFor[In, Out]) {
	if !g.pol.Enabled(name, class) {
		return
	}
	t.Name = name
	mcp.AddTool(s, t, h)
}
