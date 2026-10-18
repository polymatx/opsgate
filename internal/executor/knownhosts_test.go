package executor

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func knownHostsFile(t *testing.T, lines ...string) ssh.HostKeyCallback {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	data := ""
	for _, l := range lines {
		data += l + "\n"
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	cb, err := knownhosts.New(path)
	if err != nil {
		t.Fatal(err)
	}
	return cb
}

func line(t *testing.T, host string, pub any) string {
	t.Helper()
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return knownhosts.Line([]string{host}, k)
}

func TestKnownHostKeyAlgorithmsOnlyAsksForRecordedTypes(t *testing.T) {
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	cases := []struct {
		name  string
		lines []string
		addr  string
		want  []string
	}{
		{"ed25519 only, custom port", []string{line(t, "[127.0.0.1]:2222", edPub)}, "127.0.0.1:2222", []string{ssh.KeyAlgoED25519}},
		{"rsa only", []string{line(t, "127.0.0.1", &rsaKey.PublicKey)}, "127.0.0.1:22", []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}},
		{"all three", []string{line(t, "127.0.0.1", &rsaKey.PublicKey), line(t, "127.0.0.1", &ecKey.PublicKey), line(t, "127.0.0.1", edPub)}, "127.0.0.1:22", []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}},
		{"unknown host keeps defaults", []string{line(t, "10.0.0.9", edPub)}, "127.0.0.1:22", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := knownHostKeyAlgorithms(knownHostsFile(t, c.lines...), c.addr)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestHostKeyErrorExplainsUnknownAndChangedKeys(t *testing.T) {
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(edPub)
	unknown := hostKeyError("127.0.0.1:2222", &knownhosts.KeyError{})
	if !strings.Contains(unknown.Error(), "not in ~/.ssh/known_hosts") || !strings.Contains(unknown.Error(), "ssh -p 2222 127.0.0.1") {
		t.Fatalf("unknown host message: %v", unknown)
	}
	changed := hostKeyError("127.0.0.1:2222", &knownhosts.KeyError{Want: []knownhosts.KnownKey{{Key: k, Filename: "known_hosts", Line: 7}}})
	if !strings.Contains(changed.Error(), "does NOT match") || !strings.Contains(changed.Error(), "line 7") || !strings.Contains(changed.Error(), "ssh-keygen -R '[127.0.0.1]:2222'") {
		t.Fatalf("changed key message: %v", changed)
	}
	standard := hostKeyError("203.0.113.10:22", &knownhosts.KeyError{Want: []knownhosts.KnownKey{{Key: k, Line: 1}}})
	if !strings.Contains(standard.Error(), "ssh-keygen -R '203.0.113.10'") {
		t.Fatalf("port 22 entry: %v", standard)
	}
}
