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
)

// These tests drive a real MCP client over an in-memory transport, because the
// approval gate can only be proven end to end: a unit test that stubs the
// session cannot catch an invalid elicitation mode or a protocol version that
// forbids server-initiated requests.

// approvalHarness wires a real client/server pair around a Gate whose "local"
// executor is a fake, and returns the session plus the fake and audit path.
func approvalHarness(t *testing.T, mode config.Mode, answer string) (*mcp.ClientSession, *fakeExec, string) {
	t.Helper()

	cfg := &config.Config{
		Mode:           mode,
		DefaultHost:    "local",
		Tools:          map[string]config.ToolRule{},
		TimeoutSeconds: 5,
		MaxOutputBytes: 4096,
		Files:          config.Files{AllowPaths: []string{"/var/log"}, MaxBytes: 4096},
	}
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := audit.Open(logPath, nil)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	g := NewGate(cfg, log)
	fake := &fakeExec{res: executor.Result{Stdout: "restarted\n"}}
	g.execs["local"] = fake

	srv := mcp.NewServer(&mcp.Implementation{Name: "opsgate", Version: "test"}, nil)
	Register(srv, g)

	var opts *mcp.ClientOptions
	if answer != "" {
		opts = &mcp.ClientOptions{
			ElicitationHandler: func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
				// The operator sees the prompt here; assert it names the action.
				if !strings.Contains(req.Params.Message, "on host") {
					t.Errorf("approval prompt lacks host context: %q", req.Params.Message)
				}
				return &mcp.ElicitResult{Action: answer}, nil
			},
		}
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, opts)

	ct, st := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(context.Background(), st, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	cs, err := client.Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	return cs, fake, logPath
}

func callRestart(t *testing.T, cs *mcp.ClientSession) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "service_restart",
		Arguments: map[string]any{"name": "nginx"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	return res
}

func TestApprovalAcceptedExecutesTheCommand(t *testing.T) {
	cs, fake, logPath := approvalHarness(t, config.ModeOperate, "accept")

	res := callRestart(t, cs)

	if res.IsError {
		t.Fatalf("approved call returned an error: %s", textOf(res))
	}
	if len(fake.calls) != 1 {
		t.Fatalf("executor called %d times, want 1 — approval did not lead to execution", len(fake.calls))
	}
	if got := strings.Join(fake.calls[0], " "); got != "systemctl restart nginx" {
		t.Errorf("argv = %q", got)
	}

	recs := readAudit(t, logPath)
	var sawApproved bool
	for _, r := range recs {
		if r.Approved != nil && *r.Approved {
			sawApproved = true
		}
	}
	if !sawApproved {
		t.Errorf("audit has no record of the approval: %+v", recs)
	}
}

func TestApprovalDeclinedBlocksTheCommand(t *testing.T) {
	cs, fake, logPath := approvalHarness(t, config.ModeOperate, "decline")

	res := callRestart(t, cs)

	if !res.IsError {
		t.Error("a declined call should return an error result")
	}
	if len(fake.calls) != 0 {
		t.Errorf("executor was called %v; a declined call must never execute", fake.calls)
	}
	recs := readAudit(t, logPath)
	for _, r := range recs {
		if r.Phase == audit.PhaseIntent || r.Phase == audit.PhaseOutcome {
			t.Errorf("declined call wrote an execution record: %+v", r)
		}
	}
}

func TestApprovalCancelledBlocksTheCommand(t *testing.T) {
	cs, fake, _ := approvalHarness(t, config.ModeOperate, "cancel")

	res := callRestart(t, cs)

	if !res.IsError {
		t.Error("a cancelled call should return an error result")
	}
	if len(fake.calls) != 0 {
		t.Errorf("executor was called %v; a cancelled call must never execute", fake.calls)
	}
}

func TestClientWithoutApprovalSupportFailsClosed(t *testing.T) {
	// No ElicitationHandler: the client cannot answer. The call may fail either
	// as an error result or as a protocol error — what matters is that the
	// command never runs.
	cs, fake, _ := approvalHarness(t, config.ModeOperate, "")

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "service_restart",
		Arguments: map[string]any{"name": "nginx"},
	})
	switch {
	case err != nil:
		// Expected: the SDK reports that it cannot fulfil the input request.
	case res.IsError:
		// Also acceptable: an explicit refusal.
	default:
		t.Error("expected failure when the client cannot collect approval")
	}
	if len(fake.calls) != 0 {
		t.Errorf("executor was called %v; must fail closed", fake.calls)
	}
}

func TestObserveModeNeedsNoApprovalAndRefuses(t *testing.T) {
	cs, fake, _ := approvalHarness(t, config.ModeObserve, "accept")

	res := callRestart(t, cs)

	if !res.IsError {
		t.Error("observe mode must refuse a mutating tool even if the operator would accept")
	}
	if len(fake.calls) != 0 {
		t.Errorf("executor was called %v in observe mode", fake.calls)
	}
}

func TestFullModeExecutesWithoutPrompting(t *testing.T) {
	promptCount := 0
	cfg := &config.Config{
		Mode:           config.ModeFull,
		DefaultHost:    "local",
		Tools:          map[string]config.ToolRule{},
		TimeoutSeconds: 5,
		MaxOutputBytes: 4096,
	}
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := audit.Open(logPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })

	g := NewGate(cfg, log)
	fake := &fakeExec{res: executor.Result{Stdout: "ok\n"}}
	g.execs["local"] = fake

	srv := mcp.NewServer(&mcp.Implementation{Name: "opsgate", Version: "test"}, nil)
	Register(srv, g)

	client := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "1"}, &mcp.ClientOptions{
		ElicitationHandler: func(_ context.Context, _ *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			promptCount++
			return &mcp.ElicitResult{Action: "accept"}, nil
		},
	})
	ct, st := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(context.Background(), st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := client.Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	res := callRestart(t, cs)
	if res.IsError {
		t.Fatalf("full mode should execute: %s", textOf(res))
	}
	if len(fake.calls) != 1 {
		t.Errorf("executor called %d times, want 1", len(fake.calls))
	}
	if promptCount != 0 {
		t.Errorf("full mode prompted %d times, want 0", promptCount)
	}
}
