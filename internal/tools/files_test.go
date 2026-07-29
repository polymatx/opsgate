package tools

import (
	"testing"

	"github.com/polymatx/opsgate/internal/config"
)

func gateWithPaths(paths []string) *Gate {
	cfg := &config.Config{
		Mode:  config.ModeObserve,
		Tools: map[string]config.ToolRule{},
		Files: config.Files{AllowPaths: paths},
	}
	return NewGate(cfg, nil)
}

func TestAllowedPathAcceptsPathsInsideAllowlist(t *testing.T) {
	g := gateWithPaths([]string{"/var/log", "/etc/nginx"})

	for _, in := range []string{
		"/var/log",
		"/var/log/syslog",
		"/var/log/nginx/access.log",
		"/etc/nginx/nginx.conf",
	} {
		if _, ok := g.allowedPath(in); !ok {
			t.Errorf("allowedPath(%q) = false, want true", in)
		}
	}
}

func TestAllowedPathRejectsTraversalEscapes(t *testing.T) {
	g := gateWithPaths([]string{"/var/log"})

	for _, in := range []string{
		"/etc/shadow",
		"/var/log/../../etc/shadow",
		"/var/log/../.ssh/id_rsa",
		"/var/logsomething/file", // prefix must be a path boundary
		"/var/log/../log2/file",
		"relative/path",
		"",
		"/var/log/\x00/etc/shadow",
	} {
		if got, ok := g.allowedPath(in); ok {
			t.Errorf("allowedPath(%q) = %q, true; want false", in, got)
		}
	}
}

func TestAllowedPathNormalizesBeforeChecking(t *testing.T) {
	g := gateWithPaths([]string{"/var/log"})
	got, ok := g.allowedPath("/var/log/./nginx//access.log")
	if !ok {
		t.Fatal("expected a cleanable path inside the allowlist to be accepted")
	}
	if got != "/var/log/nginx/access.log" {
		t.Errorf("allowedPath returned %q, want the cleaned path", got)
	}
}

func TestAllowedPathSupportsGlobEntries(t *testing.T) {
	g := gateWithPaths([]string{"/srv/*/logs"})
	if _, ok := g.allowedPath("/srv/app1/logs"); !ok {
		t.Error("glob allowlist entry should match /srv/app1/logs")
	}
	if _, ok := g.allowedPath("/srv/app1/secrets"); ok {
		t.Error("glob allowlist entry should not match /srv/app1/secrets")
	}
}
