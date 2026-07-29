// shellapproval.go — binding between a shell gate escalation and the approval
// ceremony that authorizes it.
//
// An approval ceremony created for a blocked shell command carries a binding
// token derived from the exact command line (args included): the ceremony
// authorizes that command line and nothing else. When the gate re-checks a
// pending command, it consumes a matching approved ceremony server-side; a
// ceremony approved for a different command never satisfies the gate.
package workstation

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// ShellGateApprovalSubject and ShellGateApprovalAction identify approval
// ceremonies created by the shell gate.
const (
	ShellGateApprovalSubject = "shell_command"
	ShellGateApprovalAction  = "shell_operate"
)

// shellGateBindingPrefix prefixes the binding token embedded in the approval
// reason so it is greppable by operators and parseable by the gate.
const shellGateBindingPrefix = "shellgate-binding=sha256:"

// ShellCommandBindingHash returns the hex SHA-256 of the exact command line.
// The hash covers the full line, arguments included, so an approval for
// `rm /tmp/a` never authorizes `rm /etc/b`.
func ShellCommandBindingHash(command string) string {
	sum := sha256.Sum256([]byte(command))
	return hex.EncodeToString(sum[:])
}

// ShellCommandBinding returns the binding token to embed in an approval
// ceremony for command.
func ShellCommandBinding(command string) string {
	return shellGateBindingPrefix + ShellCommandBindingHash(command)
}

// ShellCommandBindingRef returns the structured immutable binding stored on
// the approval ceremony. Human-readable reasons are deliberately excluded.
func ShellCommandBindingRef(command string) string {
	return "sha256:" + ShellCommandBindingHash(command)
}

// ApprovalBindsToCommand reports whether a structured ceremony binding covers
// exactly this command line.
func ApprovalBindsToCommand(bindingHash, command string) bool {
	return bindingHash == ShellCommandBindingRef(command)
}

// ApprovalReasonMatchesBinding checks the optional human-readable shell token
// against the immutable structured binding shown to an approver.
func ApprovalReasonMatchesBinding(reason, bindingHash string) bool {
	return strings.Contains(reason, shellGateBindingPrefix+strings.TrimPrefix(bindingHash, "sha256:"))
}
