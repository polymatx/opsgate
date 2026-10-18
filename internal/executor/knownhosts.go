package executor

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
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

var hostKeyAlgoOrder = []string{
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoECDSA256,
	ssh.KeyAlgoECDSA384,
	ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoSKED25519,
	ssh.KeyAlgoSKECDSA256,
	ssh.KeyAlgoRSASHA512,
	ssh.KeyAlgoRSASHA256,
	ssh.KeyAlgoRSA,
}

func knownHostKeyAlgorithms(cb ssh.HostKeyCallback, addr string) []string {
	remote, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil
	}
	probe, err := ssh.NewPublicKey(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)))
	if err != nil {
		return nil
	}
	var keyErr *knownhosts.KeyError
	if !errors.As(cb(addr, remote, probe), &keyErr) || len(keyErr.Want) == 0 {
		return nil
	}
	known := map[string]bool{}
	for _, k := range keyErr.Want {
		switch t := k.Key.Type(); t {
		case ssh.KeyAlgoRSA:
			known[ssh.KeyAlgoRSASHA512] = true
			known[ssh.KeyAlgoRSASHA256] = true
			known[ssh.KeyAlgoRSA] = true
		default:
			known[t] = true
		}
	}
	var algos []string
	for _, a := range hostKeyAlgoOrder {
		if known[a] {
			algos = append(algos, a)
			delete(known, a)
		}
	}
	for a := range known {
		algos = append(algos, a)
	}
	return algos
}

func hostKeyError(addr string, keyErr *knownhosts.KeyError) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port = addr, "22"
	}
	if len(keyErr.Want) == 0 {
		return fmt.Errorf("ssh %s: the host key is not in ~/.ssh/known_hosts, so opsgate will not connect. "+
			"Connect once yourself (ssh -p %s %s), check the fingerprint, accept it, then retry", addr, port, host)
	}
	entry := host
	if port != "22" {
		entry = "[" + host + "]:" + port
	}
	return fmt.Errorf("ssh %s: the host key does NOT match ~/.ssh/known_hosts (line %d). "+
		"This is what a man-in-the-middle looks like; it also happens after a server is rebuilt. "+
		"Verify the new key out of band, then replace the entry (ssh-keygen -R '%s') and retry",
		addr, keyErr.Want[0].Line, entry)
}
