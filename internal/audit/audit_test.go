package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newLogger(t *testing.T) (*Logger, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path, []string{"password", "token"})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, path
}

func TestChainVerifies(t *testing.T) {
	l, path := newLogger(t)
	for i := 0; i < 5; i++ {
		if err := l.Log(Record{Time: time.Now(), Host: "local", Tool: "disk_usage", Decision: "allow"}); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	n, err := Verify(path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if n != 5 {
		t.Errorf("verified %d records, want 5", n)
	}
}

func TestVerifyDetectsEditedRecord(t *testing.T) {
	l, path := newLogger(t)
	for _, tool := range []string{"disk_usage", "service_restart", "docker_ps"} {
		if err := l.Log(Record{Time: time.Now(), Host: "local", Tool: tool, Decision: "allow"}); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	_ = l.Close()

	// Someone tries to hide that they restarted a service.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), `"tool":"service_restart"`, `"tool":"disk_usage"`, 1)
	if tampered == string(raw) {
		t.Fatal("test setup: nothing was replaced")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Verify(path); err == nil {
		t.Error("Verify() accepted a tampered record")
	}
}

func TestVerifyDetectsDeletedRecord(t *testing.T) {
	l, path := newLogger(t)
	for i := 0; i < 4; i++ {
		if err := l.Log(Record{Time: time.Now(), Host: "local", Tool: "docker_ps", Decision: "allow"}); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	_ = l.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	// Drop the second record entirely.
	kept := append([]string{lines[0]}, lines[2:]...)
	if err := os.WriteFile(path, []byte(strings.Join(kept, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Verify(path); err == nil {
		t.Error("Verify() accepted a log with a deleted record")
	}
}

func TestSecretsAreRedacted(t *testing.T) {
	l, path := newLogger(t)
	err := l.Log(Record{
		Time: time.Now(),
		Tool: "shell_exec",
		Args: map[string]any{
			"command":  "mysql -u root",
			"password": "hunter2",
			"TOKEN":    "ghp_secret",
		},
	})
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	_ = l.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	for _, secret := range []string{"hunter2", "ghp_secret"} {
		if strings.Contains(got, secret) {
			t.Errorf("audit log leaked secret %q", secret)
		}
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Error("expected [REDACTED] in the log")
	}
	if !strings.Contains(got, "mysql -u root") {
		t.Error("non-secret args should still be logged")
	}
}

func TestResumeContinuesChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")

	l1, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = l1.Log(Record{Time: time.Now(), Tool: "a"})
	_ = l1.Log(Record{Time: time.Now(), Tool: "b"})
	_ = l1.Close()

	// Restarting opsgate must extend the existing chain, not restart it.
	l2, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = l2.Log(Record{Time: time.Now(), Tool: "c"})
	_ = l2.Close()

	n, err := Verify(path)
	if err != nil {
		t.Fatalf("Verify after resume: %v", err)
	}
	if n != 3 {
		t.Errorf("verified %d records, want 3", n)
	}
}

func TestVerifyMissingFile(t *testing.T) {
	if _, err := Verify(filepath.Join(t.TempDir(), "nope.jsonl")); err == nil {
		t.Error("expected an error for a missing audit file")
	}
}
