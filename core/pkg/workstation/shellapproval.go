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

// ApprovalBindsToCommand reports whether an approval ceremony reason carries
// the binding token for exactly this command line.
func ApprovalBindsToCommand(approvalReason, command string) bool {
	return strings.Contains(approvalReason, ShellCommandBinding(command))
}
