package executor

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// knownHostsCallback verifies remote host keys against the user's known_hosts.
// opsgate never accepts unknown host keys: an agent-driven tool that trusts any
// key on first use would be trivially MITM-able.
func knownHostsCallback() (ssh.HostKeyCallback, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("locate home dir: %w", err)
	}
	path := filepath.Join(home, ".ssh", "known_hosts")
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf(
			"%s not found: connect once with the ssh client to record the host key, then retry", path)
	}
	cb, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("parse known_hosts: %w", err)
	}
	return cb, nil
}
