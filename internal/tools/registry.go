// Package tools defines opsgate's structured MCP tools and the gate every
// call passes through: policy check -> human approval -> execute -> audit.
package tools

import (
	"context"
	"errors"
	"fmt"
	"os"
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
	cfg *config.Config
	pol *policy.Engine
	log *audit.Logger
	// mu guards execs and dialMu. It is never held across a network dial.
	mu    sync.Mutex
	execs map[string]executor.Executor
	// dialMu serialises dials per host, so a slow or unreachable host delays
	// only calls to that host rather than every concurrent call.
	dialMu map[string]*sync.Mutex
	dialer func(name string, h config.Host, timeout time.Duration) (executor.Executor, error)
}

// NewGate builds a Gate. Executors are created lazily on first use per host.
func NewGate(cfg *config.Config, log *audit.Logger) *Gate {
	return &Gate{
		cfg:    cfg,
		pol:    policy.New(cfg),
		log:    log,
		execs:  map[string]executor.Executor{},
		dialMu: map[string]*sync.Mutex{},
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
//
// The dial happens without the Gate mutex held, guarded instead by a per-host
// lock: an unreachable host must not stall concurrent calls to other hosts.
func (g *Gate) executorFor(host string) (executor.Executor, error) {
	g.mu.Lock()
	if e, ok := g.execs[host]; ok {
		g.mu.Unlock()
		return e, nil
	}
	if host == "local" {
		e := executor.Local{}
		g.execs[host] = e
		g.mu.Unlock()
		return e, nil
	}
	h, ok := g.cfg.Hosts[host]
	if !ok {
		names := g.hostNames()
		g.mu.Unlock()
		return nil, fmt.Errorf("unknown host %q; configured hosts: %s", host, strings.Join(names, ", "))
	}
	hostLock, ok := g.dialMu[host]
	if !ok {
		hostLock = &sync.Mutex{}
		g.dialMu[host] = hostLock
	}
	timeout := time.Duration(g.cfg.TimeoutSeconds) * time.Second
	g.mu.Unlock()

	hostLock.Lock()
	defer hostLock.Unlock()

	// Another caller may have connected while we waited for the host lock.
	g.mu.Lock()
	if e, ok := g.execs[host]; ok {
		g.mu.Unlock()
		return e, nil
	}
	g.mu.Unlock()

	e, err := g.dialer(host, h, timeout)
	if err != nil {
		// Deliberately not cached: the next call should retry the dial.
		return nil, err
	}
	g.mu.Lock()
	g.execs[host] = e
	g.mu.Unlock()
	return e, nil
}

// evict drops a host's cached executor so the next call redials. Without this a
// single dropped SSH connection would wedge every later call to that host for
// the lifetime of the process, since NewSession on a dead client fails forever.
func (g *Gate) evict(host string) {
	if host == "local" {
		return
	}
	g.mu.Lock()
	e, ok := g.execs[host]
	delete(g.execs, host)
	g.mu.Unlock()
	if ok {
		_ = e.Close()
	}
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
	// requireTarget rejects the call when target is empty. Set it whenever the
	// tool's primary argument is mandatory, so an empty string cannot slip past
	// the charset and allow_targets checks.
	requireTarget bool
	// targetIsPath marks target as a filesystem path already validated by
	// allowedPath, exempting it from the unit-name charset.
	targetIsPath bool
}

// run executes a gated call and returns text output for the model.
func (g *Gate) run(ctx context.Context, req *mcp.CallToolRequest, c call) (*mcp.CallToolResult, error) {
	rec := audit.Record{
		Time: time.Now(),
		Host: c.host,
		Tool: c.tool,
		Args: c.args,
	}

	// A tool whose primary argument is mandatory must not proceed with it empty:
	// an empty target skips both the charset check and the allow_targets check.
	if c.requireTarget && c.target == "" {
		rec.Decision = "deny"
		rec.Err = "missing required target"
		g.logRec(rec)
		return errResult(fmt.Sprintf("Refused: %s requires a non-empty target.", c.tool)), nil
	}

	// Defense in depth: reject unusual target strings even though argv is never
	// interpolated into a shell. Paths are exempt from the unit-name charset —
	// they have already been constrained by allowedPath, and legitimate paths
	// contain characters (spaces, backslashes) that the charset excludes.
	if c.target != "" && !c.targetIsPath && !policy.ValidTarget(c.target) {
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
		approved, pending, err := g.askApproval(ctx, req, c)
		if err != nil {
			rec.Err = err.Error()
			g.logRec(rec)
			return errResult(fmt.Sprintf(
				"Approval could not be requested (%v). This client may not support approval prompts; "+
					"set tools.%s.approval: never or mode: full to allow it without prompting.", err, c.tool)), nil
		}
		if pending != nil {
			// The operator has not answered yet. Record that we asked, then hand
			// the request back to the client to collect the decision and retry.
			rec.Decision = "approval_requested"
			g.logRec(rec)
			return pending, nil
		}
		rec.Approved = &approved
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

	// State-changing actions must never execute unaudited. Write the intent
	// first: if that write fails, refuse rather than act without a record.
	if c.class != policy.Observe {
		intent := rec
		intent.Phase = audit.PhaseIntent
		if err := g.logIntent(intent); err != nil {
			return errResult(fmt.Sprintf(
				"Refused: opsgate could not write the audit record for this action (%v), "+
					"so it will not perform it.", err)), nil
		}
	}

	runCtx, cancel := context.WithTimeout(ctx, time.Duration(g.cfg.TimeoutSeconds)*time.Second)
	defer cancel()

	res, runErr := e.Run(runCtx, c.argv)
	if c.class != policy.Observe {
		rec.Phase = audit.PhaseOutcome
	}
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
		// A transport-level failure (as opposed to a non-zero exit) may mean the
		// connection is dead. Drop it so the next call reconnects instead of
		// failing identically forever.
		g.evict(c.host)
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

// approvalKey identifies opsgate's confirmation among a call's input requests.
const approvalKey = "opsgate_approval"

// mrtrProtocolVersion is the first MCP protocol version that forbids
// server-initiated elicitation and requires the multi round-trip form instead
// (SEP-2322). Sessions at or above it must be asked via InputRequests.
const mrtrProtocolVersion = "2026-07-28"

// askApproval obtains the operator's decision for a mutating call.
//
// Two protocol shapes exist and both are supported:
//
//   - From 2026-07-28 the server may not send elicitation/create while serving a
//     request. Instead the handler returns a result carrying InputRequests; the
//     client collects the answer and retries the same call with InputResponses.
//     That retry is what `pending != nil` sets up.
//   - Older sessions still accept a server-initiated elicitation, which can be
//     answered inline.
//
// When pending is non-nil the caller must return it unchanged so the round trip
// can complete. Any error means no decision was obtained, and the caller must
// fail closed.
func (g *Gate) askApproval(ctx context.Context, req *mcp.CallToolRequest, c call) (approved bool, pending *mcp.CallToolResult, err error) {
	if req == nil || req.Session == nil {
		return false, nil, errors.New("no client session is available to ask for approval")
	}

	// Is this the retry that carries the operator's answer?
	if req.Params != nil {
		if resp, ok := req.Params.InputResponses[approvalKey]; ok {
			res, ok := resp.(*mcp.ElicitResult)
			if !ok {
				return false, nil, fmt.Errorf("unexpected approval response of type %T", resp)
			}
			// Only an explicit accept approves; decline and cancel both deny.
			return res.Action == "accept", nil, nil
		}
	}

	prompt := &mcp.ElicitParams{Message: g.approvalPrompt(c)}

	if ip := req.Session.InitializeParams(); ip != nil && ip.ProtocolVersion >= mrtrProtocolVersion {
		// An input-required result must carry only the input requests: the SDK
		// rejects a result that also has content.
		return false, &mcp.CallToolResult{
			InputRequests: mcp.InputRequestMap{approvalKey: prompt},
		}, nil
	}

	// Legacy path: Mode is left empty so the SDK infers "form", and no schema is
	// requested — the decision is carried by the action, not by form content.
	res, err := req.Session.Elicit(ctx, prompt)
	if err != nil {
		return false, nil, err
	}
	return res.Action == "accept", nil, nil
}

// approvalPrompt is what the operator reads before deciding.
func (g *Gate) approvalPrompt(c call) string {
	var b strings.Builder
	fmt.Fprintf(&b, "opsgate: allow %s on host %q?\n\n", c.tool, c.host)
	if c.summary != "" {
		b.WriteString(c.summary)
		b.WriteString("\n\n")
	}
	fmt.Fprintf(&b, "Command: %s", executor.QuoteArgv(c.argv))
	return b.String()
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
// A failed write is reported on stderr: it must not pass silently, but a
// refusal that cannot be logged is still a refusal, so it does not abort.
func (g *Gate) logRec(r audit.Record) {
	if g.log == nil {
		return
	}
	if err := g.log.Log(r); err != nil {
		fmt.Fprintf(os.Stderr, "opsgate: AUDIT WRITE FAILED for %s on %s: %v\n", r.Tool, r.Host, err)
	}
}

// logIntent writes the pre-execution record for a state-changing call and
// reports whether it succeeded, so the caller can refuse to act when it did not.
func (g *Gate) logIntent(r audit.Record) error {
	if g.log == nil {
		return nil
	}
	if err := g.log.Log(r); err != nil {
		fmt.Fprintf(os.Stderr, "opsgate: AUDIT WRITE FAILED, refusing to execute %s on %s: %v\n", r.Tool, r.Host, err)
		return err
	}
	return nil
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
