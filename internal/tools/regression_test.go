package tools

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/polymatx/opsgate/internal/config"
	"github.com/polymatx/opsgate/internal/executor"
	"github.com/polymatx/opsgate/internal/policy"
)

// Regressions for defects found by audit. Each test names the property that
// must hold, not the bug that once broke it.

func TestEmptyTargetCannotBypassAllowTargets(t *testing.T) {
	// journal_tail with no unit reads the WHOLE journal — strictly broader than
	// any allowed unit — so it must be refused once an allowlist exists.
	g, fake, _ := gateWith(t, config.ModeFull, map[string]config.ToolRule{
		"journal_tail": {AllowTargets: []string{"myapp.service"}},
	})

	res, err := g.run(context.Background(), nil, call{
		tool:  "journal_tail",
		class: policy.Observe,
		host:  "local",
		// no target: the agent omitted the unit
		argv: []string{"journalctl", "-n", "100"},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !res.IsError {
		t.Error("omitting the target must not bypass allow_targets")
	}
	if len(fake.calls) != 0 {
		t.Errorf("executor was called %v", fake.calls)
	}
}

func TestEmptyRequiredTargetIsRefused(t *testing.T) {
	g, fake, _ := gateWith(t, config.ModeFull, nil)

	res, err := g.run(context.Background(), nil, call{
		tool:          "service_restart",
		class:         policy.Mutate,
		host:          "local",
		target:        "",
		requireTarget: true,
		argv:          []string{"systemctl", "restart", ""},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !res.IsError {
		t.Error("an empty required target must be refused")
	}
	if len(fake.calls) != 0 {
		t.Errorf("executor was called %v", fake.calls)
	}
}

func TestPathTargetsAreNotSubjectToUnitNameCharset(t *testing.T) {
	// A legitimate path with a space is inside the allowlist and must be read,
	// even though the unit-name charset would reject it.
	g, fake, _ := gateWith(t, config.ModeObserve, nil)

	res, err := g.run(context.Background(), nil, call{
		tool:         "file_read",
		class:        policy.Observe,
		host:         "local",
		target:       "/var/log/my app/error.log",
		targetIsPath: true,
		argv:         []string{"head", "-c", "4096", "/var/log/my app/error.log"},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.IsError {
		t.Errorf("a valid path with a space was refused: %s", textOf(res))
	}
	if len(fake.calls) != 1 {
		t.Errorf("executor called %d times, want 1", len(fake.calls))
	}
}

func TestGlobAllowPathCoversFilesBeneathIt(t *testing.T) {
	g := gateWithPaths([]string{"/srv/*/logs"})

	for _, in := range []string{"/srv/app1/logs", "/srv/app1/logs/error.log", "/srv/app1/logs/nested/x.log"} {
		if _, ok := g.allowedPath(in); !ok {
			t.Errorf("allowedPath(%q) = false, want true", in)
		}
	}
	for _, in := range []string{"/srv/app1/secrets", "/srv/app1/secrets/key.pem", "/srv/logs", "/etc/shadow"} {
		if got, ok := g.allowedPath(in); ok {
			t.Errorf("allowedPath(%q) = %q,true; want false", in, got)
		}
	}
}

// deadExec fails every Run with a transport-style error, like a dead SSH client.
type deadExec struct{ runs int }

func (d *deadExec) Name() string { return "dead" }
func (d *deadExec) Close() error { return nil }
func (d *deadExec) Run(context.Context, []string) (executor.Result, error) {
	d.runs++
	return executor.Result{}, errors.New("ssh session: use of closed network connection")
}

func TestDeadExecutorIsEvictedSoNextCallRedials(t *testing.T) {
	cfg := &config.Config{
		Mode:           config.ModeObserve,
		DefaultHost:    "remote",
		Tools:          map[string]config.ToolRule{},
		TimeoutSeconds: 5,
		MaxOutputBytes: 4096,
		Hosts:          map[string]config.Host{"remote": {Addr: "10.0.0.1"}},
	}
	g := NewGate(cfg, nil)

	dials := 0
	dead := &deadExec{}
	g.dialer = func(string, config.Host, time.Duration) (executor.Executor, error) {
		dials++
		return dead, nil
	}

	for i := 0; i < 3; i++ {
		res, err := g.run(context.Background(), nil, call{
			tool:  "disk_usage",
			class: policy.Observe,
			host:  "remote",
			argv:  []string{"df", "-h"},
		})
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if !res.IsError {
			t.Fatalf("run %d should report failure", i)
		}
	}
	// Each failure must evict, so each attempt redials rather than reusing the
	// dead connection forever.
	if dials != 3 {
		t.Errorf("dials = %d, want 3 (one per attempt after eviction)", dials)
	}
}

// slowDialExec lets a test hold a dial open to observe locking behaviour.
type blockingDialer struct {
	release chan struct{}
	started chan string
}

func TestSlowDialToOneHostDoesNotBlockAnotherHost(t *testing.T) {
	cfg := &config.Config{
		Mode:           config.ModeObserve,
		DefaultHost:    "local",
		Tools:          map[string]config.ToolRule{},
		TimeoutSeconds: 5,
		MaxOutputBytes: 4096,
		Hosts: map[string]config.Host{
			"slow": {Addr: "10.0.0.1"},
			"fast": {Addr: "10.0.0.2"},
		},
	}
	g := NewGate(cfg, nil)

	bd := &blockingDialer{release: make(chan struct{}), started: make(chan string, 2)}
	g.dialer = func(name string, _ config.Host, _ time.Duration) (executor.Executor, error) {
		bd.started <- name
		if name == "slow" {
			<-bd.release // hang until the test allows it
		}
		return &fakeExec{res: executor.Result{Stdout: "ok\n"}}, nil
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = g.executorFor("slow")
	}()

	// Wait until the slow dial is genuinely in progress.
	if got := <-bd.started; got != "slow" {
		t.Fatalf("expected the slow dial to start first, got %q", got)
	}

	// The fast host must connect while the slow dial is still hanging.
	fastDone := make(chan error, 1)
	go func() {
		_, err := g.executorFor("fast")
		fastDone <- err
	}()

	select {
	case err := <-fastDone:
		if err != nil {
			t.Errorf("fast host dial failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("a hanging dial to one host blocked a dial to another host")
	}

	close(bd.release)
	wg.Wait()
}

func TestNginxReloadRefusalIsAudited(t *testing.T) {
	// nginx -t fails, so the reload must be refused AND recorded under its own
	// tool name, not silently dropped from the log.
	g, fake, logPath := gateWith(t, config.ModeFull, nil)
	fake.res = executor.Result{Stderr: "nginx: configuration file test failed\n", ExitCode: 1}

	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "1"}, nil)
	Register(srv, g)

	res := g.refuseNginxForTest(t, context.Background())
	if res == nil || !res.IsError {
		t.Fatal("expected a refusal")
	}

	recs := readAudit(t, logPath)
	var found bool
	for _, r := range recs {
		if r.Tool == "nginx_reload" && r.Decision == "deny" {
			found = true
		}
	}
	if !found {
		t.Errorf("no nginx_reload deny record in audit log: %+v", recs)
	}
}

// refuseNginxForTest exercises the nginx_reload preflight refusal path.
func (g *Gate) refuseNginxForTest(t *testing.T, ctx context.Context) *mcp.CallToolResult {
	t.Helper()
	check, err := g.run(ctx, nil, call{
		tool:  "nginx_test",
		class: policy.Observe,
		host:  "local",
		argv:  []string{"nginx", "-t"},
		args:  map[string]any{"host": "local", "phase": "preflight"},
	})
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if !check.IsError {
		t.Fatal("preflight should have failed")
	}
	return g.refuse("local", "nginx_reload", map[string]any{"host": "local"},
		"Refused to reload: nginx -t failed.\n\n"+textOf(check))
}

func TestFileReadEnforcesMaxBytes(t *testing.T) {
	// files.max_bytes must reach the command so a huge file is bounded remotely.
	cfg := &config.Config{
		Mode:           config.ModeObserve,
		DefaultHost:    "local",
		Tools:          map[string]config.ToolRule{},
		TimeoutSeconds: 5,
		MaxOutputBytes: 49152,
		Files:          config.Files{AllowPaths: []string{"/var/log"}, MaxBytes: 4096},
	}
	g := NewGate(cfg, nil)
	fake := &fakeExec{res: executor.Result{Stdout: "data"}}
	g.execs["local"] = fake

	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "1"}, nil)
	Register(srv, g)

	ct, st := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(context.Background(), st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "1"}, nil).
		Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "file_read",
		Arguments: map[string]any{"path": "/var/log/syslog"},
	}); err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	if len(fake.calls) != 1 {
		t.Fatalf("executor called %d times, want 1", len(fake.calls))
	}
	got := strings.Join(fake.calls[0], " ")
	if !strings.Contains(got, "4096") {
		t.Errorf("argv %q does not carry the configured max_bytes (4096)", got)
	}
}

func TestKnownToolsMatchesRegisteredTools(t *testing.T) {
	// config.KnownTools is used to reject typos in the tools: map. It must stay
	// in sync with what is actually registered.
	yes := true
	cfg := &config.Config{
		Mode:        config.ModeFull,
		DefaultHost: "local",
		Tools:       map[string]config.ToolRule{"shell_exec": {Enabled: &yes}},
	}
	g := NewGate(cfg, nil)
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "1"}, nil)
	Register(srv, g)

	ct, st := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(context.Background(), st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "1"}, nil).
		Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	registered := map[string]bool{}
	for _, tl := range res.Tools {
		registered[tl.Name] = true
		if !config.KnownTools[tl.Name] {
			t.Errorf("tool %q is registered but missing from config.KnownTools", tl.Name)
		}
	}
	for name := range config.KnownTools {
		if !registered[name] {
			t.Errorf("config.KnownTools lists %q but no such tool is registered", name)
		}
	}
}
