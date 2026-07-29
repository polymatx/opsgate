package policy

import (
	"testing"

	"github.com/polymatx/opsgate/internal/config"
)

func engine(mode config.Mode, tools map[string]config.ToolRule) *Engine {
	cfg := &config.Config{Mode: mode, Tools: tools}
	if cfg.Tools == nil {
		cfg.Tools = map[string]config.ToolRule{}
	}
	return New(cfg)
}

func TestObserveModeRefusesMutation(t *testing.T) {
	e := engine(config.ModeObserve, nil)

	if d, _ := e.Check("local", "service_status", Observe, "nginx"); d != Allow {
		t.Errorf("read-only tool in observe mode: got %v, want allow", d)
	}
	if d, _ := e.Check("local", "service_restart", Mutate, "nginx"); d != Deny {
		t.Errorf("mutating tool in observe mode: got %v, want deny", d)
	}
	if d, _ := e.Check("local", "shell_exec", Shell, ""); d != Deny {
		t.Errorf("shell in observe mode: got %v, want deny", d)
	}
}

func TestOperateModeRequiresApprovalForMutation(t *testing.T) {
	e := engine(config.ModeOperate, nil)

	if d, _ := e.Check("local", "docker_logs", Observe, "api"); d != Allow {
		t.Errorf("read-only tool: got %v, want allow", d)
	}
	if d, _ := e.Check("local", "docker_restart", Mutate, "api"); d != NeedsApproval {
		t.Errorf("mutating tool in operate mode: got %v, want needs_approval", d)
	}
}

func TestFullModeAllowsMutationWithoutApproval(t *testing.T) {
	e := engine(config.ModeFull, nil)
	if d, _ := e.Check("local", "service_restart", Mutate, "nginx"); d != Allow {
		t.Errorf("mutating tool in full mode: got %v, want allow", d)
	}
}

func TestApprovalAlwaysOverridesFullMode(t *testing.T) {
	e := engine(config.ModeFull, map[string]config.ToolRule{
		"service_stop": {Approval: "always"},
	})
	if d, _ := e.Check("local", "service_stop", Mutate, "nginx"); d != NeedsApproval {
		t.Errorf("approval:always in full mode: got %v, want needs_approval", d)
	}
}

func TestAllowTargetsRestrictsTargets(t *testing.T) {
	e := engine(config.ModeFull, map[string]config.ToolRule{
		"service_restart": {AllowTargets: []string{"nginx", "myapp*"}},
	})

	for _, tc := range []struct {
		target string
		want   Decision
	}{
		{"nginx", Allow},
		{"myapp-worker", Allow},
		{"postgresql", Deny},
		{"sshd", Deny},
	} {
		if d, _ := e.Check("local", "service_restart", Mutate, tc.target); d != tc.want {
			t.Errorf("target %q: got %v, want %v", tc.target, d, tc.want)
		}
	}
}

func TestShellDisabledByDefault(t *testing.T) {
	e := engine(config.ModeFull, nil)
	if e.Enabled("shell_exec", Shell) {
		t.Error("shell_exec should be disabled unless explicitly enabled")
	}
	if !e.Enabled("service_status", Observe) {
		t.Error("read-only tools should be enabled by default")
	}
}

func TestExplicitlyDisabledToolIsDenied(t *testing.T) {
	no := false
	e := engine(config.ModeFull, map[string]config.ToolRule{
		"service_stop": {Enabled: &no},
	})
	if e.Enabled("service_stop", Mutate) {
		t.Error("Enabled() should honour enabled:false")
	}
	if d, _ := e.Check("local", "service_stop", Mutate, "nginx"); d != Deny {
		t.Errorf("disabled tool: got %v, want deny", d)
	}
}

func TestPerHostModeOverride(t *testing.T) {
	cfg := &config.Config{
		Mode:  config.ModeFull,
		Tools: map[string]config.ToolRule{},
		Hosts: map[string]config.Host{
			"prod": {Addr: "10.0.0.1", Mode: config.ModeObserve},
		},
	}
	e := New(cfg)
	if d, _ := e.Check("prod", "service_restart", Mutate, "nginx"); d != Deny {
		t.Errorf("prod host pinned to observe: got %v, want deny", d)
	}
	if d, _ := e.Check("local", "service_restart", Mutate, "nginx"); d != Allow {
		t.Errorf("local host inherits full: got %v, want allow", d)
	}
}

func TestValidTargetRejectsInjectionShapes(t *testing.T) {
	for _, bad := range []string{
		"", "nginx; reboot", "nginx && reboot", "$(reboot)", "`reboot`",
		"nginx|sh", "nginx\nreboot", "nginx 'x'", "a\x00b",
	} {
		if ValidTarget(bad) {
			t.Errorf("ValidTarget(%q) = true, want false", bad)
		}
	}
	for _, good := range []string{
		"nginx", "docker.service", "myapp-worker", "user@host",
		"/var/log/syslog", "postgresql@14-main",
	} {
		if !ValidTarget(good) {
			t.Errorf("ValidTarget(%q) = false, want true", good)
		}
	}
}
