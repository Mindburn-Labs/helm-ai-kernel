package runtime

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

type EgressProxy interface {
	Start(EgressProxyRequest) (EgressProxyHandle, error)
}

type EgressProxyRequest struct {
	LaunchID   string   `json:"launch_id"`
	Allowlist  []string `json:"allowlist"`
	ReceiptDir string   `json:"receipt_dir,omitempty"`
}

type EgressProxyHandle struct {
	ProxyURL           string       `json:"proxy_url"`
	ReceiptRef         string       `json:"receipt_ref"`
	ReceiptDir         string       `json:"receipt_dir,omitempty"`
	Allowlist          []string     `json:"allowlist"`
	NetworkName        string       `json:"network_name,omitempty"`
	ProxyContainerID   string       `json:"proxy_container_id,omitempty"`
	ProxyContainerName string       `json:"proxy_container_name,omitempty"`
	Stop               func() error `json:"-"`
}

type StaticEgressProxy struct {
	ProxyURL   string
	ReceiptRef string
}

func (p StaticEgressProxy) Start(req EgressProxyRequest) (EgressProxyHandle, error) {
	if p.ProxyURL == "" {
		return EgressProxyHandle{}, errors.New("egress proxy URL is required")
	}
	if p.ReceiptRef == "" {
		return EgressProxyHandle{}, errors.New("egress proxy receipt ref is required")
	}
	if err := ValidateOpenRouterAllowlist(req.Allowlist); err != nil {
		return EgressProxyHandle{}, err
	}
	return EgressProxyHandle{ProxyURL: p.ProxyURL, ReceiptRef: p.ReceiptRef, Allowlist: append([]string{}, req.Allowlist...)}, nil
}

func NetworkAllowed(destination string, allowlist []string) bool {
	normalizedDestination := normalizeDestination(destination)
	for _, allowed := range allowlist {
		if normalizedDestination == normalizeDestination(allowed) {
			return true
		}
	}
	return false
}

func ValidateOpenRouterAllowlist(allowlist []string) error {
	for _, allowed := range allowlist {
		destination := normalizeDestination(allowed)
		switch destination {
		case "openrouter.ai:443", "api.openrouter.ai:443":
			continue
		default:
			return fmt.Errorf("local-container egress allowlist can only contain OpenRouter HTTPS endpoints, got %q", allowed)
		}
	}
	return nil
}

func normalizeDestination(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	parsed, err := url.Parse(trimmed)
	if err == nil && parsed.Host != "" {
		host := parsed.Host
		if !strings.Contains(host, ":") {
			if parsed.Scheme == "https" {
				host += ":443"
			} else if parsed.Scheme == "http" {
				host += ":80"
			}
		}
		return strings.ToLower(host)
	}
	if !strings.Contains(trimmed, ":") {
		trimmed += ":443"
	}
	return strings.ToLower(trimmed)
}
