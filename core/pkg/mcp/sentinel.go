package mcp

import (
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
)

// SentinelConnector handles external execution proposals from BGT Labs Sentinel.
type SentinelConnector struct {
	guard *guardian.Guardian
}

// SentinelIntent maps BGT Labs Sentinel's universal authorization request payload.
type SentinelIntent struct {
	Principal string                 `json:"principal"`
	Action    string                 `json:"action"`
	Resource  string                 `json:"resource"`
	Context   map[string]interface{} `json:"context"`
}
