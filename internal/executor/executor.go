// Package executor runs commands locally or over SSH.
//
// Commands are always described as argv slices, never as shell strings. The
// local executor passes argv straight to exec.Command (no shell involved). The
// SSH executor must produce a string for the remote shell, so every element is
// single-quoted by ShellQuote before joining — the remote shell therefore sees
// each argv element as one literal word, and metacharacters in agent-supplied
// arguments cannot start a new command.
package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"net"
)

// Result is the outcome of one command.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
}

// Executor runs an argv on some machine.
type Executor interface {
	Run(ctx context.Context, argv []string) (Result, error)
	Close() error
	Name() string
}

// ShellQuote wraps s in single quotes for POSIX shells, escaping embedded
// single quotes. The result is always exactly one shell word.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// QuoteArgv renders argv as a single shell-safe command string.
func QuoteArgv(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		parts[i] = ShellQuote(a)
	}
	return strings.Join(parts, " ")
}

// Local runs commands on the machine opsgate is running on.
type Local struct{}

func (Local) Name() string { return "local" }
func (Local) Close() error { return nil }

func (Local) Run(ctx context.Context, argv []string) (Result, error) {
	if len(argv) == 0 {
		return Result{}, errors.New("empty command")
	}
	start := time.Now()
	// No shell: argv[0] is resolved via PATH and arguments are passed as-is.
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	killProcessGroup(cmd)
	cmd.WaitDelay = closeGrace
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	res := Result{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: time.Since(start),
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		res.ExitCode = -1
		return res, ctxErr
	}
	var ee *exec.ExitError
	switch {
	case err == nil:
		res.ExitCode = 0
	case errors.As(err, &ee):
		res.ExitCode = ee.ExitCode()
	default:
		return res, err
	}
	return res, nil
}

// SSH runs commands on a remote host over SSH.
type SSH struct {
	name      string
	client    *ssh.Client
	stop      chan struct{}
	closeOnce sync.Once
}

const (
	keepaliveEvery   = 15 * time.Second
	keepaliveTimeout = 10 * time.Second
)

func (s *SSH) Name() string { return s.name }

func (s *SSH) Close() error {
	var err error
	s.closeOnce.Do(func() {
		if s.stop != nil {
			close(s.stop)
		}
		if s.client != nil {
			err = s.client.Close()
		}
	})
	return err
}

func (s *SSH) keepalive() {
	t := time.NewTicker(keepaliveEvery)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
		}
		replied := make(chan error, 1)
		go func() {
			_, _, err := s.client.SendRequest("keepalive@openssh.com", true, nil)
			replied <- err
		}()
		select {
		case <-s.stop:
			return
		case err := <-replied:
			if err == nil {
				continue
			}
		case <-time.After(keepaliveTimeout):
		}
		_ = s.Close()
		return
	}
}

// DialSSH connects to addr. It authenticates with keyPath when given,
// otherwise with ssh-agent. Host keys are verified against known_hosts.
func DialSSH(name, addr, user, keyPath string, port int, timeout time.Duration) (*SSH, error) {
	if user == "" {
		user = os.Getenv("USER")
	}
	if !strings.Contains(addr, ":") {
		if port == 0 {
			port = 22
		}
		addr = fmt.Sprintf("%s:%d", addr, port)
	}
	auths, err := sshAuths(keyPath)
	if err != nil {
		return nil, err
	}
	hostKeyCallback, err := knownHostsCallback()
	if err != nil {
		return nil, err
	}
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:              user,
		Auth:              auths,
		HostKeyCallback:   hostKeyCallback,
		HostKeyAlgorithms: knownHostKeyAlgorithms(hostKeyCallback, addr),
		Timeout:           timeout,
	})
	if err != nil {
		var keyErr *knownhosts.KeyError
		if errors.As(err, &keyErr) {
			return nil, hostKeyError(addr, keyErr)
		}
		return nil, fmt.Errorf("ssh dial %s: %w", addr, err)
	}
	s := &SSH{name: name, client: client, stop: make(chan struct{})}
	go s.keepalive()
	return s, nil
}

// closeGrace is how long Run waits, after closing a timed-out session, for
// x/crypto/ssh's output-copying goroutines to finish before it is safe to read
// the output buffers.
const closeGrace = 2 * time.Second

func (s *SSH) Run(ctx context.Context, argv []string) (Result, error) {
	if len(argv) == 0 {
		return Result{}, errors.New("empty command")
	}
	start := time.Now()

	// Every argv element is single-quoted, so the remote shell treats it as one
	// literal word regardless of the characters it contains.
	cmdLine := QuoteArgv(argv)

	var stdout, stderr bytes.Buffer
	done := make(chan error, 1)
	// sessCh publishes the session so the timeout path can close it. Session
	// creation happens on this goroutine too: on a half-open connection
	// NewSession can block indefinitely, and it must not outlast ctx.
	sessCh := make(chan *ssh.Session, 1)

	go func() {
		sess, err := s.client.NewSession()
		if err != nil {
			done <- fmt.Errorf("ssh session: %w", err)
			return
		}
		defer sess.Close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			done <- ctxErr
			return
		}
		// Buffers must be attached before the session is published, so the
		// timeout path never races with this assignment.
		sess.Stdout, sess.Stderr = &stdout, &stderr
		sessCh <- sess
		done <- sess.Run(cmdLine)
	}()

	select {
	case <-ctx.Done():
		// Signal then close so a hung remote command cannot pin the session.
		select {
		case sess := <-sessCh:
			_ = sess.Signal(ssh.SIGKILL)
			_ = sess.Close()
		default:
			// Still connecting; nothing to signal.
		}
		// Do not touch stdout/stderr until the goroutine — and with it
		// x/crypto/ssh's io.Copy into these buffers — has finished. bytes.Buffer
		// is not safe for concurrent use, so reading here while a copier is
		// still writing would be a data race. Closing the session unblocks Run.
		select {
		case <-done:
			return Result{
				Stdout:   stdout.String(),
				Stderr:   stderr.String(),
				ExitCode: -1,
				Duration: time.Since(start),
			}, ctx.Err()
		case <-time.After(closeGrace):
			// The copiers may still be running: abandon the output rather than
			// read a buffer that is concurrently written.
			return Result{
				ExitCode: -1,
				Duration: time.Since(start),
			}, ctx.Err()
		}
	case err := <-done:
		res := Result{
			Stdout:   stdout.String(),
			Stderr:   stderr.String(),
			Duration: time.Since(start),
		}
		var ee *ssh.ExitError
		switch {
		case err == nil:
			res.ExitCode = 0
		case errors.As(err, &ee):
			res.ExitCode = ee.ExitStatus()
		default:
			return res, err
		}
		return res, nil
	}
}

func sshAuths(keyPath string) ([]ssh.AuthMethod, error) {
	var auths []ssh.AuthMethod
	if keyPath != "" {
		key, err := os.ReadFile(expandHome(keyPath))
		if err != nil {
			return nil, fmt.Errorf("read ssh key: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("parse ssh key (encrypted keys are not supported; use ssh-agent): %w", err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(conn).Signers))
		}
	}
	if len(auths) == 0 {
		return nil, errors.New("no ssh auth available: set hosts.<name>.key or run ssh-agent")
	}
	return auths, nil
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return home + p[1:]
		}
	}
	return p
}
