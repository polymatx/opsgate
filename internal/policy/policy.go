// Package policy decides whether a tool call is allowed, denied, or needs
// human approval. Decisions are deny-by-default: anything not explicitly
// permitted by the mode and tool rules is refused.
package policy

import (
	"fmt"
	"path"
	"regexp"

	"github.com/polymatx/opsgate/internal/config"
)

// Class describes what a tool does to the target system.
type Class int

const (
	// Observe tools only read state.
	Observe Class = iota
	// Mutate tools change state (restart services, etc.).
	Mutate
	// Shell tools run freeform commands. Disabled unless opted in.
	Shell
)

// Decision is the outcome of a policy check.
type Decision int

const (
	Deny Decision = iota
	Allow
	NeedsApproval
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	case NeedsApproval:
		return "needs_approval"
	default:
		return "deny"
	}
}

// targetRe is the defense-in-depth charset for service/container/unit names.
// Commands are always built as argv (never string-interpolated into a shell),
// but constraining names further shrinks the attack surface.
var targetRe = regexp.MustCompile(`^[A-Za-z0-9@:._/-]+$`)

// ValidTarget reports whether a user-supplied target name is safe to pass on.
func ValidTarget(t string) bool {
	return t != "" && len(t) <= 256 && targetRe.MatchString(t)
}

// Engine evaluates tool calls against the loaded config.
type Engine struct {
	cfg *config.Config
}

func New(cfg *config.Config) *Engine {
	return &Engine{cfg: cfg}
}

// Enabled reports whether a tool should be registered at all.
func (e *Engine) Enabled(tool string, class Class) bool {
	rule, hasRule := e.cfg.Tools[tool]
	if hasRule && rule.Enabled != nil {
		return *rule.Enabled
	}
	// shell_exec is opt-in.
	return class != Shell
}

// Check returns the decision for calling tool (of class) against target on host.
// target may be empty for tools that take no target (e.g. disk_usage).
func (e *Engine) Check(host, tool string, class Class, target string) (Decision, string) {
	mode := e.cfg.HostMode(host)
	rule := e.cfg.Tools[tool]

	if !e.Enabled(tool, class) {
		return Deny, fmt.Sprintf("tool %s is disabled by policy", tool)
	}

	// Target allowlist applies to every class.
	if target != "" && len(rule.AllowTargets) > 0 && !matchAny(rule.AllowTargets, target) {
		return Deny, fmt.Sprintf("target %q is not in allow_targets for %s", target, tool)
	}

	switch class {
	case Observe:
		return Allow, ""
	case Mutate:
		switch mode {
		case config.ModeObserve:
			return Deny, fmt.Sprintf("host is in observe mode; %s is a mutating tool", tool)
		case config.ModeOperate:
			if rule.Approval == "never" {
				return Allow, ""
			}
			return NeedsApproval, ""
		case config.ModeFull:
			if rule.Approval == "always" {
				return NeedsApproval, ""
			}
			return Allow, ""
		}
	case Shell:
		// Reaching here means shell_exec was explicitly enabled.
		if mode == config.ModeObserve {
			return Deny, "host is in observe mode; shell_exec is not available"
		}
		if rule.Approval == "never" && mode == config.ModeFull {
			return Allow, ""
		}
		return NeedsApproval, ""
	}
	return Deny, "unknown tool class"
}

func matchAny(patterns []string, target string) bool {
	for _, p := range patterns {
		if ok, err := path.Match(p, target); err == nil && ok {
			return true
		}
	}
	return false
}
