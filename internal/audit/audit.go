// Package audit writes a tamper-evident JSONL audit log. Every record embeds
// the SHA-256 of the previous record, forming a hash chain: editing or
// deleting any line breaks verification of every line after it.
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	maxFieldBytes = 2048
	keepBytes     = 256
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
	path       string
	size       int64
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
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit open: %w", err)
	}
	unlock, err := lockFile(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("audit lock: %w", err)
	}
	defer unlock()
	seq, prev, size, err := tail(path)
	if err != nil {
		f.Close()
		return nil, err
	}
	rk := make(map[string]bool, len(redactKeys))
	for _, k := range redactKeys {
		rk[strings.ToLower(k)] = true
	}
	return &Logger{f: f, path: path, size: size, seq: seq, prevHash: prev, redactKeys: rk}, nil
}

// tail reads the last record to resume the chain.
func tail(path string) (seq int64, prevHash string, size int64, err error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return 0, genesis, 0, nil
	}
	if err != nil {
		return 0, "", 0, fmt.Errorf("audit read: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return 0, "", 0, fmt.Errorf("audit read: %w", err)
	}
	r, found, err := lastRecord(io.NewSectionReader(f, 0, st.Size()), path)
	if err != nil {
		return 0, "", 0, err
	}
	if !found {
		return 0, genesis, st.Size(), nil
	}
	return r.Seq, r.Hash, st.Size(), nil
}

func lastRecord(src io.Reader, path string) (Record, bool, error) {
	var last Record
	found := false
	lineNo := 0
	err := eachLine(src, func(line string) error {
		lineNo++
		if line == "" {
			return nil
		}
		// Refuse to resume from a damaged log. Skipping a bad line would append a
		// chain that starts from the wrong predecessor, which is far worse than
		// telling the operator their audit file needs attention.
		r, err := decodeStrict(line)
		if err != nil {
			return fmt.Errorf("audit log %s line %d is corrupt (%w); "+
				"move it aside or repair it before starting opsgate", path, lineNo, err)
		}
		last, found = r, true
		return nil
	})
	return last, found, err
}

func eachLine(src io.Reader, fn func(string) error) error {
	br := bufio.NewReader(src)
	for {
		b, err := br.ReadBytes('\n')
		if len(b) > 0 {
			if ferr := fn(string(bytes.TrimSpace(b))); ferr != nil {
				return ferr
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("audit read: %w", err)
		}
	}
}

func (l *Logger) catchUp() error {
	st, err := l.f.Stat()
	if err != nil {
		return fmt.Errorf("audit stat: %w", err)
	}
	switch {
	case st.Size() == l.size:
		return nil
	case st.Size() < l.size:
		seq, prev, size, err := tail(l.path)
		if err != nil {
			return err
		}
		l.seq, l.prevHash, l.size = seq, prev, size
		return nil
	}
	r, found, err := lastRecord(io.NewSectionReader(l.f, l.size, st.Size()-l.size), l.path)
	if err != nil {
		return err
	}
	if found {
		l.seq, l.prevHash = r.Seq, r.Hash
	}
	l.size = st.Size()
	return nil
}

// Log writes one record, filling seq, hashes, and redacting sensitive args.
func (l *Logger) Log(r Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	unlock, err := lockFile(l.f)
	if err != nil {
		return fmt.Errorf("audit lock: %w", err)
	}
	defer unlock()
	if err := l.catchUp(); err != nil {
		return err
	}
	l.seq++
	r.Seq = l.seq
	r.Time = r.Time.UTC()
	r.Args = l.redact(r.Args)
	r.Err = capString(r.Err)
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
	l.size += int64(len(line) + 1)
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
		out[k] = capValue(v)
	}
	return out
}

func capValue(v any) any {
	switch t := v.(type) {
	case string:
		return capString(t)
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = capValue(x)
		}
		return m
	case []any:
		s := make([]any, len(t))
		for i, x := range t {
			s[i] = capValue(x)
		}
		return s
	case []string:
		s := make([]any, len(t))
		for i, x := range t {
			s[i] = capString(x)
		}
		return s
	}
	return v
}

func capString(s string) string {
	if len(s) <= maxFieldBytes {
		return s
	}
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%s…[truncated: %d bytes, sha256 %s]", strings.ToValidUTF8(s[:keepBytes], ""), len(s), hex.EncodeToString(sum[:]))
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
	prev := genesis
	n := 0
	lineNo := 0
	err = eachLine(f, func(line string) error {
		lineNo++
		if line == "" {
			return nil
		}
		// Strict decoding matters: the chain authenticates the Record fields, so
		// an attacker could otherwise splice extra JSON keys ("approved_by":
		// "alice") into an existing line and still have it verify. Anything the
		// hash does not cover must be rejected outright.
		r, err := decodeStrict(line)
		if err != nil {
			return fmt.Errorf("line %d: %w", lineNo, err)
		}
		if r.PrevHash != prev {
			return fmt.Errorf("line %d: chain broken (prev_hash %q, want %q)", lineNo, r.PrevHash, prev)
		}
		want := r.Hash
		got, err := hashRecord(r)
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("line %d: record tampered (hash mismatch)", lineNo)
		}
		prev = want
		n++
		return nil
	})
	return n, err
}
