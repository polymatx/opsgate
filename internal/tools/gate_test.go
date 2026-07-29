package tools

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/polymatx/opsgate/internal/audit"
	"github.com/polymatx/opsgate/internal/config"
	"github.com/polymatx/opsgate/internal/executor"
	"github.com/polymatx/opsgate/internal/policy"
)

// fakeExec records what it was asked to run instead of running it.
type fakeExec struct {
	calls [][]string
	res   executor.Result
}

func (f *fakeExec) Name() string { return "fake" }
func (f *fakeExec) Close() error { return nil }
func (f *fakeExec) Run(_ context.Context, argv []string) (executor.Result, error) {
	f.calls = append(f.calls, argv)
	return f.res, nil
}

// gateWith builds a Gate whose "local" executor is a fake, plus a real audit log.
func gateWith(t *testing.T, mode config.Mode, tools map[string]config.ToolRule) (*Gate, *fakeExec, string) {
	t.Helper()
	if tools == nil {
		tools = map[string]config.ToolRule{}
	}
	cfg := &config.Config{
		Mode:           mode,
		DefaultHost:    "local",
		Tools:          tools,
		TimeoutSeconds: 5,
		MaxOutputBytes: 4096,
		Files:          config.Files{AllowPaths: []string{"/var/log"}},
	}
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := audit.Open(logPath, []string{"password"})
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	g := NewGate(cfg, log)
	fake := &fakeExec{res: executor.Result{Stdout: "ok\n"}}
	g.execs["local"] = fake
	return g, fake, logPath
}

func readAudit(t *testing.T, path string) []audit.Record {
	t.Helper()
	if _, err := audit.Verify(path); err != nil {
		t.Fatalf("audit chain invalid: %v", err)
	}
	return parseRecords(t, path)
}

func TestGateExecutesAllowedObserveCall(t *testing.T) {
	g, fake, logPath := gateWith(t, config.ModeObserve, nil)

	res, err := g.run(context.Background(), nil, call{
		tool:   "service_status",
		class:  policy.Observe,
		host:   "local",
		target: "nginx",
		argv:   []string{"systemctl", "status", "nginx"},
		args:   map[string]any{"name": "nginx"},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.IsError {
		t.Errorf("expected success, got error result: %s", textOf(res))
	}
	if len(fake.calls) != 1 {
		t.Fatalf("executor called %d times, want 1", len(fake.calls))
	}
	if got := strings.Join(fake.calls[0], " "); got != "systemctl status nginx" {
		t.Errorf("argv = %q", got)
	}

	recs := readAudit(t, logPath)
	if len(recs) != 1 || recs[0].Decision != "allow" {
		t.Errorf("audit = %+v, want one allow record", recs)
	}
}

func TestGateBlocksMutationInObserveModeWithoutRunningAnything(t *testing.T) {
	g, fake, logPath := gateWith(t, config.ModeObserve, nil)

	res, err := g.run(context.Background(), nil, call{
		tool:   "service_restart",
		class:  policy.Mutate,
		host:   "local",
		target: "nginx",
		argv:   []string{"systemctl", "restart", "nginx"},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !res.IsError {
		t.Error("expected a refusal")
	}
	// The critical assertion: nothing reached the machine.
	if len(fake.calls) != 0 {
		t.Errorf("executor was called %v; a denied call must never execute", fake.calls)
	}
	recs := readAudit(t, logPath)
	if len(recs) != 1 || recs[0].Decision != "deny" {
		t.Errorf("audit = %+v, want one deny record", recs)
	}
}

func TestGateRefusesInjectionTargetBeforeExecuting(t *testing.T) {
	g, fake, logPath := gateWith(t, config.ModeFull, nil)

	res, err := g.run(context.Background(), nil, call{
		tool:   "service_restart",
		class:  policy.Mutate,
		host:   "local",
		target: "nginx; rm -rf /",
		argv:   []string{"systemctl", "restart", "nginx; rm -rf /"},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !res.IsError {
		t.Error("expected a refusal for an invalid target")
	}
	if len(fake.calls) != 0 {
		t.Errorf("executor was called %v; an invalid target must never execute", fake.calls)
	}
	recs := readAudit(t, logPath)
	if len(recs) != 1 || recs[0].Err != "invalid target" {
		t.Errorf("audit = %+v, want one invalid-target deny", recs)
	}
}

func TestGateFailsClosedWhenApprovalCannotBeRequested(t *testing.T) {
	// operate mode + no session => elicitation impossible. The call must be
	// refused, not quietly executed.
	g, fake, _ := gateWith(t, config.ModeOperate, nil)

	res, err := g.run(context.Background(), nil, call{
		tool:   "service_restart",
		class:  policy.Mutate,
		host:   "local",
		target: "nginx",
		argv:   []string{"systemctl", "restart", "nginx"},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !res.IsError {
		t.Error("expected failure when approval cannot be requested")
	}
	if len(fake.calls) != 0 {
		t.Errorf("executor was called %v; must fail closed", fake.calls)
	}
}

func TestGateAllowsMutationInFullMode(t *testing.T) {
	g, fake, logPath := gateWith(t, config.ModeFull, nil)

	res, err := g.run(context.Background(), nil, call{
		tool:   "service_restart",
		class:  policy.Mutate,
		host:   "local",
		target: "nginx",
		argv:   []string{"systemctl", "restart", "nginx"},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.IsError {
		t.Errorf("expected success in full mode, got: %s", textOf(res))
	}
	if len(fake.calls) != 1 {
		t.Errorf("executor called %d times, want 1", len(fake.calls))
	}
	// A mutating call writes intent before executing and the outcome after, so
	// an action can never be absent from the log.
	recs := readAudit(t, logPath)
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2 (intent + outcome): %+v", len(recs), recs)
	}
	if recs[0].Phase != audit.PhaseIntent || recs[0].Decision != "allow" {
		t.Errorf("record 1 = phase %q decision %q, want intent/allow", recs[0].Phase, recs[0].Decision)
	}
	if recs[1].Phase != audit.PhaseOutcome || recs[1].ExitCode != 0 {
		t.Errorf("record 2 = phase %q exit %d, want outcome/0", recs[1].Phase, recs[1].ExitCode)
	}
}

func TestGateRefusalIsAudited(t *testing.T) {
	g, _, logPath := gateWith(t, config.ModeObserve, nil)

	g.refuse("local", "file_read", map[string]any{"path": "/root/.ssh/id_rsa"}, "outside allowed paths")

	recs := readAudit(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if recs[0].Decision != "deny" || recs[0].Tool != "file_read" {
		t.Errorf("record = %+v, want a file_read deny", recs[0])
	}
}

func TestGateReportsNonZeroExitAsError(t *testing.T) {
	g, fake, _ := gateWith(t, config.ModeObserve, nil)
	fake.res = executor.Result{Stdout: "", Stderr: "Unit not found\n", ExitCode: 4}

	res, err := g.run(context.Background(), nil, call{
		tool:   "service_status",
		class:  policy.Observe,
		host:   "local",
		target: "ghost",
		argv:   []string{"systemctl", "status", "ghost"},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !res.IsError {
		t.Error("a non-zero exit code should surface as an error result")
	}
	if txt := textOf(res); !strings.Contains(txt, "exit code 4") || !strings.Contains(txt, "Unit not found") {
		t.Errorf("result text = %q, want exit code and stderr", txt)
	}
}

func TestGateTruncatesLargeOutput(t *testing.T) {
	g, fake, _ := gateWith(t, config.ModeObserve, nil)
	fake.res = executor.Result{Stdout: strings.Repeat("x", 10_000)}

	res, err := g.run(context.Background(), nil, call{
		tool:  "journal_tail",
		class: policy.Observe,
		host:  "local",
		argv:  []string{"journalctl"},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	txt := textOf(res)
	if len(txt) > 4096+128 {
		t.Errorf("output length %d exceeds max_output_bytes plus notice", len(txt))
	}
	if !strings.Contains(txt, "truncated") {
		t.Error("truncated output should say so")
	}
}

func TestGateUnknownHostIsReportedNotExecuted(t *testing.T) {
	g, fake, _ := gateWith(t, config.ModeObserve, nil)

	res, err := g.run(context.Background(), nil, call{
		tool:  "disk_usage",
		class: policy.Observe,
		host:  "nope",
		argv:  []string{"df", "-h"},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !res.IsError {
		t.Error("expected an error for an unknown host")
	}
	if len(fake.calls) != 0 {
		t.Errorf("executor was called %v for an unknown host", fake.calls)
	}
}

func TestRegisterOmitsShellExecByDefault(t *testing.T) {
	g, _, _ := gateWith(t, config.ModeFull, nil)
	s := mcp.NewServer(&mcp.Implementation{Name: "test"}, nil)
	Register(s, g)

	// shell_exec must not be registered unless explicitly enabled.
	if g.pol.Enabled("shell_exec", policy.Shell) {
		t.Error("shell_exec should be disabled by default")
	}

	yes := true
	g2, _, _ := gateWith(t, config.ModeFull, map[string]config.ToolRule{
		"shell_exec": {Enabled: &yes},
	})
	if !g2.pol.Enabled("shell_exec", policy.Shell) {
		t.Error("shell_exec should be enabled when opted in")
	}
}
