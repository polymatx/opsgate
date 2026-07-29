package tools

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/polymatx/opsgate/internal/audit"
)

// parseRecords reads every audit record from a JSONL file.
func parseRecords(t *testing.T, path string) []audit.Record {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer f.Close()

	var out []audit.Record
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r audit.Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("parse audit record: %v", err)
		}
		out = append(out, r)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan audit log: %v", err)
	}
	return out
}
