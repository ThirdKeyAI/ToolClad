package executor

import (
	"fmt"

	"github.com/thirdkeyai/toolclad/pkg/manifest"
)

// GateDecision is a policy gate's verdict on one call: allow it, or deny it
// with a reason that reaches the caller.
type GateDecision struct {
	Allowed bool
	Reason  string
}

// Allow returns an allowing decision.
func Allow() GateDecision { return GateDecision{Allowed: true} }

// Deny returns a denying decision carrying reason.
func Deny(reason string) GateDecision { return GateDecision{Reason: reason} }

// Gate decides whether a call may proceed. It is consulted after argument
// validation, with the validated values (declared arguments only, defaults
// applied), and before anything is spawned, any HTTP request is made or any
// MCP envelope is built. A denial runs nothing.
//
// ToolClad does not evaluate policy itself. [tool.cedar] declares the
// resource and action for an embedding runtime's Cedar evaluator; wiring
// that evaluator into a Gate is the embedder's job.
type Gate func(m *manifest.Manifest, args map[string]string) GateDecision

// DefaultGate denies a manifest that sets human_approval = true or whose
// risk_tier is high or critical, and allows everything else.
func DefaultGate(m *manifest.Manifest, _ map[string]string) GateDecision {
	if m.Tool.HumanApproval {
		return Deny("manifest requires human approval (human_approval = true)")
	}
	switch m.Tool.RiskTier {
	case "high", "critical":
		return Deny(fmt.Sprintf("risk_tier '%s' requires explicit approval", m.Tool.RiskTier))
	}
	return Allow()
}

// ApproveGate allows every call: the caller has approved it explicitly.
func ApproveGate(*manifest.Manifest, map[string]string) GateDecision { return Allow() }

// GateDeniedError is returned when a gate denies a call. Its message is
// "policy gate denied: <reason>".
type GateDeniedError struct {
	Reason string
}

func (e *GateDeniedError) Error() string { return "policy gate denied: " + e.Reason }

// consultGate runs gate (DefaultGate when nil) and turns a denial into a
// *GateDeniedError.
func consultGate(gate Gate, m *manifest.Manifest, cleaned map[string]string) error {
	if gate == nil {
		gate = DefaultGate
	}
	// The gate gets its own copy so it cannot alter what runs.
	view := make(map[string]string, len(cleaned))
	for k, v := range cleaned {
		view[k] = v
	}
	if d := gate(m, view); !d.Allowed {
		return &GateDeniedError{Reason: d.Reason}
	}
	return nil
}
