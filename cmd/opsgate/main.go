// Command opsgate is a safety gate between AI agents and your servers:
// an MCP server exposing structured, policy-checked, audited operations.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/polymatx/opsgate/internal/audit"
	"github.com/polymatx/opsgate/internal/config"
	"github.com/polymatx/opsgate/internal/tools"
	"github.com/polymatx/opsgate/internal/version"
)

const usage = `opsgate — the safety gate between AI agents and your servers

Usage:
  opsgate serve [--config FILE] [--http ADDR]   Run the MCP server (stdio by default)
  opsgate init [--config FILE]                  Write a starter config file
  opsgate audit verify [--config FILE]          Verify the audit log hash chain
  opsgate audit path [--config FILE]            Print the audit log path
  opsgate version                               Print version information

Flags:
  --config FILE   Config path (default: ./opsgate.yaml, then ~/.opsgate/config.yaml)
  --http ADDR     Serve streamable HTTP on ADDR instead of stdio (e.g. :8080)
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "opsgate: "+err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Print(usage)
		return nil
	}
	switch args[0] {
	case "serve":
		return cmdServe(args[1:])
	case "init":
		return cmdInit(args[1:])
	case "audit":
		return cmdAudit(args[1:])
	case "version", "--version", "-v":
		fmt.Printf("opsgate %s (commit %s, built %s)\n", version.Version, version.Commit, version.Date)
		return nil
	case "help", "--help", "-h":
		fmt.Print(usage)
		return nil
	default:
		return fmt.Errorf("unknown command %q\n\n%s", args[0], usage)
	}
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file path")
	httpAddr := fs.String("http", "", "serve streamable HTTP on this address")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if *httpAddr != "" {
		cfg.HTTP.Addr = *httpAddr
	}

	log, err := audit.Open(cfg.Audit.Path, cfg.Audit.RedactKeys)
	if err != nil {
		return err
	}
	defer log.Close()

	gate := tools.NewGate(cfg, log)
	defer gate.Close()

	newServer := func() *mcp.Server {
		s := mcp.NewServer(&mcp.Implementation{
			Name:    "opsgate",
			Title:   "opsgate — safe server operations",
			Version: version.Version,
		}, &mcp.ServerOptions{
			Instructions: instructions(cfg),
		})
		tools.Register(s, gate)
		return s
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Startup banner goes to stderr: stdout is the stdio JSON-RPC channel.
	fmt.Fprintf(os.Stderr, "opsgate %s | mode=%s | default_host=%s | audit=%s\n",
		version.Version, cfg.Mode, cfg.DefaultHost, cfg.Audit.Path)

	if cfg.HTTP.Addr != "" {
		return serveHTTP(ctx, cfg, newServer)
	}
	return newServer().Run(ctx, &mcp.StdioTransport{})
}

func serveHTTP(ctx context.Context, cfg *config.Config, newServer func() *mcp.Server) error {
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return newServer()
	}, nil)

	var root http.Handler = handler
	if cfg.HTTP.AuthToken != "" {
		root = bearerAuth(cfg.HTTP.AuthToken, handler)
	} else {
		fmt.Fprintln(os.Stderr,
			"opsgate: WARNING — http.auth_token is not set; anyone who can reach this port can drive your servers")
	}

	srv := &http.Server{
		Addr:              cfg.HTTP.Addr,
		Handler:           root,
		ReadHeaderTimeout: 10 * time.Second,
	}
	// ListenAndServe returns ErrServerClosed the moment Shutdown is called, so
	// the process must wait for Shutdown itself to finish. Returning early would
	// let the caller close executors and the audit log while in-flight tool calls
	// are still running — an action could execute with no record of it.
	shutdownDone := make(chan error, 1)
	go func() {
		<-ctx.Done()
		fmt.Fprintln(os.Stderr, "opsgate: shutting down, waiting for in-flight calls…")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		shutdownDone <- srv.Shutdown(shutdownCtx)
	}()

	fmt.Fprintf(os.Stderr, "opsgate: listening on %s (streamable HTTP)\n", cfg.HTTP.Addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	if err := <-shutdownDone; err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}

// bearerAuth requires a matching bearer token. Comparison is constant-time-ish
// via subtle-free length+equality on short tokens; tokens are compared whole.
func bearerAuth(token string, next http.Handler) http.Handler {
	want := "Bearer " + token
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		if len(got) != len(want) || !constantTimeEqual(got, want) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="opsgate"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func constantTimeEqual(a, b string) bool {
	var diff byte
	for i := 0; i < len(a) && i < len(b); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0 && len(a) == len(b)
}

func instructions(cfg *config.Config) string {
	var b strings.Builder
	b.WriteString("opsgate exposes structured, audited operations on real servers.\n\n")
	fmt.Fprintf(&b, "Current mode: %s. ", cfg.Mode)
	switch cfg.Mode {
	case config.ModeObserve:
		b.WriteString("Only read-only tools will succeed; anything that changes state is refused.\n")
	case config.ModeOperate:
		b.WriteString("Read-only tools run freely; tools that change state require the human to approve each call.\n")
	case config.ModeFull:
		b.WriteString("All enabled tools run without prompting. Every call is still audited.\n")
	}
	b.WriteString("\nGuidance:\n")
	b.WriteString("- Diagnose before acting: read status and logs, state your conclusion, then use a mutating tool.\n")
	b.WriteString("- Prefer the specific tool (service_restart) over shell_exec; shell_exec is often disabled.\n")
	b.WriteString("- A refusal is final. Do not retry it a different way or try to work around the policy.\n")
	if len(cfg.Hosts) > 0 {
		names := make([]string, 0, len(cfg.Hosts)+1)
		names = append(names, "local")
		for n := range cfg.Hosts {
			names = append(names, n)
		}
		fmt.Fprintf(&b, "\nHosts: %s (default: %s).\n", strings.Join(names, ", "), cfg.DefaultHost)
	}
	return b.String()
}

func cmdAudit(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: opsgate audit verify|path [--config FILE]")
	}
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "config file path")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	switch args[0] {
	case "path":
		fmt.Println(cfg.Audit.Path)
		return nil
	case "verify":
		n, err := audit.Verify(cfg.Audit.Path)
		if err != nil {
			return fmt.Errorf("audit chain INVALID after %d records: %w", n, err)
		}
		fmt.Printf("audit chain OK: %d records verified in %s\n", n, cfg.Audit.Path)
		return nil
	default:
		return fmt.Errorf("unknown audit subcommand %q", args[0])
	}
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	cfgPath := fs.String("config", "opsgate.yaml", "where to write the config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := os.Stat(*cfgPath); err == nil {
		return fmt.Errorf("%s already exists; refusing to overwrite it", *cfgPath)
	}
	if err := os.WriteFile(*cfgPath, []byte(starterConfig), 0o600); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n\nNext: review the file, then run\n  opsgate serve --config %s\n", *cfgPath, *cfgPath)
	return nil
}

const starterConfig = `# opsgate configuration
# Docs: https://github.com/polymatx/opsgate

# observe = read-only | operate = writes need approval | full = no prompts
mode: observe

default_host: local

# hosts:
#   web1:
#     addr: 203.0.113.10
#     user: root
#     key: ~/.ssh/id_ed25519
#     mode: observe          # per-host override

files:
  allow_paths:
    - /var/log
    - /etc/nginx
    - /etc/systemd

audit:
  path: ~/.opsgate/audit.jsonl

# Per-tool rules. Anything not listed uses the mode default.
tools:
  shell_exec:
    enabled: false          # freeform shell is opt-in
  service_restart:
    allow_targets: ["nginx", "docker", "myapp*"]

timeout_seconds: 30
max_output_bytes: 49152

# Remote transport. Leave addr empty to use stdio.
# http:
#   addr: "127.0.0.1:8080"
#   auth_token: "generate-a-long-random-token"
`
