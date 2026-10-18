package audit

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTwoLoggersOnOneFileKeepOneChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, l := range []*Logger{a, b} {
		wg.Add(1)
		go func(l *Logger) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if err := l.Log(Record{Time: time.Now(), Host: "local", Tool: "system_info", Decision: "allow"}); err != nil {
					t.Error(err)
				}
			}
		}(l)
	}
	wg.Wait()
	a.Close()
	b.Close()
	n, err := Verify(path)
	if err != nil || n != 100 {
		t.Fatalf("verify = %d, %v; want 100 records and a valid chain", n, err)
	}
}

func TestOversizedArgumentIsCappedAndLogStillReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	huge := strings.Repeat("A", 2<<20)
	if err := l.Log(Record{Time: time.Now(), Host: "local", Tool: "service_restart", Args: map[string]any{"name": huge}, Decision: "deny", Err: huge}); err != nil {
		t.Fatal(err)
	}
	l.Close()
	st, _ := os.Stat(path)
	if st.Size() > 8*1024 {
		t.Fatalf("log line is %d bytes; oversized fields must be capped", st.Size())
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "truncated: 2097152 bytes, sha256 ") {
		t.Fatalf("capped field should keep length and digest: %s", data[:300])
	}
	if _, err := Open(path, nil); err != nil {
		t.Fatalf("reopen after oversized argument: %v", err)
	}
	if n, err := Verify(path); err != nil || n != 1 {
		t.Fatalf("verify = %d, %v", n, err)
	}
}

func TestVerifyReadsLinesLongerThanOneMiB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	l.Log(Record{Time: time.Now(), Host: "local", Tool: "system_info", Decision: "allow"})
	l.Close()
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(`{"seq":2,"host":"` + strings.Repeat("x", 2<<20) + `"}` + "\n")
	f.Close()
	n, err := Verify(path)
	if n != 1 || err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("verify = %d, %v; want the long line to be read and reported as line 2", n, err)
	}
}
