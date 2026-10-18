//go:build !unix

package executor

import "os/exec"

func killProcessGroup(*exec.Cmd) {}
