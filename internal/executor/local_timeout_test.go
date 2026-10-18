//go:build unix

package executor

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLocalTimeoutKillsTheWholePipeline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	res, err := Local{}.Run(ctx, []string{"sh", "-c", "sleep 30 | cat"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if res.ExitCode != -1 {
		t.Fatalf("exit code = %d, want -1", res.ExitCode)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("Run returned after %s; the pipeline outlived its timeout", d)
	}
}
