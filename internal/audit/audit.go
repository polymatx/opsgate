// Package audit writes a tamper-evident JSONL audit log. Every record embeds
// the SHA-256 of the previous record, forming a hash chain: editing or
// deleting any line breaks verification of every line after it.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Phase distinguishes the two records a state-changing call produces.
const (
	// PhaseIntent is written before a mutating command runs, so an executed
	// action can never be missing from the log.
	PhaseIntent = "intent"
	// PhaseOutcome carries the result of the command.
	PhaseOutcome = "outcome"
)

// Record is one audited tool call.
type Record struct {
	Seq  int64     `json:"seq"`
	Time time.Time `json:"time"`
	Host string    `json:"host"`
	Tool string    `json:"tool"`
	// Phase is PhaseIntent or PhaseOutcome for mutating calls, empty for
	// read-only calls and refusals, which produce a single record.
	Phase      string         `json:"phase,omitempty"`
	Args       map[string]any `json:"args,omitempty"`
	Decision   string         `json:"decision"`
	Approved   *bool          `json:"approved,omitempty"`
	ExitCode   int            `json:"exit_code"`
	DurationMS int64          `json:"duration_ms"`
	OutputSHA  string         `json:"output_sha256,omitempty"`
	OutputLen  int            `json:"output_len"`
	Err        string         `json:"error,omitempty"`
	PrevHash   string         `json:"prev_hash"`
	Hash       string         `json:"hash"`
}

// Logger appends records to a JSONL file.
type Logger struct {
	mu         sync.Mutex
	f          *os.File
	seq        int64
	prevHash   string
	redactKeys map[string]bool
}

const genesis = "genesis"

// Open creates (or resumes) the audit log at path.
func Open(path string, redactKeys []string) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("audit dir: %w", err)
	}
	seq, prev, err := tail(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit open: %w", err)
	}
	rk := make(map[string]bool, len(redactKeys))
	for _, k := range redactKeys {
		rk[strings.ToLower(k)] = true
	}
	return &Logger{f: f, seq: seq, prevHash: prev, redactKeys: rk}, nil
}

// tail reads the last record to resume the chain.
func tail(path string) (seq int64, prevHash string, err error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return 0, genesis, nil
	}
	if err != nil {
		return 0, "", fmt.Errorf("audit read: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	var last Record
	found := false
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		// Refuse to resume from a damaged log. Skipping a bad line would append a
		// chain that starts from the wrong predecessor, which is far worse than
		// telling the operator their audit file needs attention.
		r, err := decodeStrict(line)
		if err != nil {
			return 0, "", fmt.Errorf("audit log %s line %d is corrupt (%w); "+
				"move it aside or repair it before starting opsgate", path, lineNo, err)
		}
		last, found = r, true
	}
	if err := sc.Err(); err != nil {
		return 0, "", fmt.Errorf("audit read: %w", err)
	}
	if !found {
		return 0, genesis, nil
	}
	return last.Seq, last.Hash, nil
}

// Log writes one record, filling seq, hashes, and redacting sensitive args.
func (l *Logger) Log(r Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	r.Seq = l.seq
	r.Time = r.Time.UTC()
	r.Args = l.redact(r.Args)
	r.PrevHash = l.prevHash
	r.Hash = ""
	h, err := hashRecord(r)
	if err != nil {
		return err
	}
	r.Hash = h
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("audit write: %w", err)
	}
	l.prevHash = r.Hash
	return nil
}

func (l *Logger) Close() error { return l.f.Close() }

func (l *Logger) redact(args map[string]any) map[string]any {
	if args == nil {
		return nil
	}
	out := make(map[string]any, len(args))
	for k, v := range args {
		if l.redactKeys[strings.ToLower(k)] {
			out[k] = "[REDACTED]"
			continue
		}
		out[k] = v
	}
	return out
}

// hashRecord hashes the canonical JSON of the record with Hash cleared.
func hashRecord(r Record) (string, error) {
	r.Hash = ""
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// SumOutput returns the SHA-256 hex digest of tool output for the log.
func SumOutput(out []byte) string {
	sum := sha256.Sum256(out)
	return hex.EncodeToString(sum[:])
}

// decodeStrict parses one log line, rejecting any field that is not part of
// Record and therefore not covered by the hash chain.
func decodeStrict(line string) (Record, error) {
	var r Record
	dec := json.NewDecoder(strings.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return r, fmt.Errorf("record is not a valid audit entry: %w", err)
	}
	// Exactly one JSON value per line; trailing content would not be hashed.
	if dec.More() {
		return r, errors.New("record has trailing content after the JSON object")
	}
	return r, nil
}

// Verify walks a JSONL audit file and checks the hash chain. It returns the
// number of valid records, or an error naming the first broken line.
func Verify(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	prev := genesis
	n := 0
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		// Strict decoding matters: the chain authenticates the Record fields, so
		// an attacker could otherwise splice extra JSON keys ("approved_by":
		// "alice") into an existing line and still have it verify. Anything the
		// hash does not cover must be rejected outright.
		r, err := decodeStrict(line)
		if err != nil {
			return n, fmt.Errorf("line %d: %w", lineNo, err)
		}
		if r.PrevHash != prev {
			return n, fmt.Errorf("line %d: chain broken (prev_hash %q, want %q)", lineNo, r.PrevHash, prev)
		}
		want := r.Hash
		got, err := hashRecord(r)
		if err != nil {
			return n, err
		}
		if got != want {
			return n, fmt.Errorf("line %d: record tampered (hash mismatch)", lineNo)
		}
		prev = want
		n++
	}
	return n, sc.Err()
}
