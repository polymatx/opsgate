package config

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "opsgate.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultIsObserveMode(t *testing.T) {
	c := Default()
	if c.Mode != ModeObserve {
		t.Errorf("default mode = %q, want observe (safe default)", c.Mode)
	}
	if c.DefaultHost != "local" {
		t.Errorf("default host = %q, want local", c.DefaultHost)
	}
}

func TestLoadAppliesDefaults(t *testing.T) {
	c, err := Load(write(t, "mode: operate\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.TimeoutSeconds != 30 {
		t.Errorf("TimeoutSeconds = %d, want 30", c.TimeoutSeconds)
	}
	if c.MaxOutputBytes == 0 {
		t.Error("MaxOutputBytes should have a default")
	}
	if len(c.Audit.RedactKeys) == 0 {
		t.Error("RedactKeys should have defaults")
	}
	if len(c.Files.AllowPaths) == 0 {
		t.Error("AllowPaths should have defaults")
	}
}

func TestLoadRejectsInvalidMode(t *testing.T) {
	if _, err := Load(write(t, "mode: yolo\n")); err == nil {
		t.Error("expected an error for an invalid mode")
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	// A typo in a security-relevant key must fail loudly, not be ignored.
	if _, err := Load(write(t, "mode: observe\nmodee: full\n")); err == nil {
		t.Error("expected an error for an unknown field")
	}
}

func TestLoadRejectsHostWithoutAddr(t *testing.T) {
	if _, err := Load(write(t, "hosts:\n  web1:\n    user: root\n")); err == nil {
		t.Error("expected an error for a host with no addr")
	}
}

func TestLoadRejectsReservedLocalHostName(t *testing.T) {
	if _, err := Load(write(t, "hosts:\n  local:\n    addr: 10.0.0.1\n")); err == nil {
		t.Error("expected an error for redefining the reserved host name 'local'")
	}
}

func TestLoadRejectsUndefinedDefaultHost(t *testing.T) {
	if _, err := Load(write(t, "default_host: web9\n")); err == nil {
		t.Error("expected an error when default_host is not defined")
	}
}

func TestHostModeOverride(t *testing.T) {
	c, err := Load(write(t, `
mode: full
hosts:
  prod:
    addr: 10.0.0.1
    mode: observe
  staging:
    addr: 10.0.0.2
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := c.HostMode("prod"); got != ModeObserve {
		t.Errorf("HostMode(prod) = %q, want observe", got)
	}
	if got := c.HostMode("staging"); got != ModeFull {
		t.Errorf("HostMode(staging) = %q, want full (inherited)", got)
	}
	if got := c.HostMode("local"); got != ModeFull {
		t.Errorf("HostMode(local) = %q, want full (inherited)", got)
	}
}

func TestLoadMissingFileFallsBackToDefault(t *testing.T) {
	// An explicit path that does not exist is an error the operator must see.
	if _, err := Load(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Error("expected an error for an explicitly named missing config")
	}
}
