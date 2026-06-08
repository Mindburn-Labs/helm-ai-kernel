package runtime

import (
	"errors"
	"net/url"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/modelproviders"
)

type EgressProxy interface {
	Start(EgressProxyRequest) (EgressProxyHandle, error)
}

type EgressProxyRequest struct {
	LaunchID           string   `json:"launch_id"`
	Allowlist          []string `json:"allowlist"`
	ReceiptDir         string   `json:"receipt_dir,omitempty"`
	PayloadInspection  string   `json:"payload_inspection,omitempty"`
	NetworkProof       string   `json:"network_proof,omitempty"`
	TokenBrokerEnabled bool     `json:"token_broker_enabled"`
}

type EgressProxyHandle struct {
	ProxyURL           string       `json:"proxy_url"`
	ReceiptRef         string       `json:"receipt_ref"`
	ReceiptPath        string       `json:"receipt_path,omitempty"`
	ReceiptDir         string       `json:"receipt_dir,omitempty"`
	Allowlist          []string     `json:"allowlist"`
	NetworkName        string       `json:"network_name,omitempty"`
	ProxyContainerID   string       `json:"proxy_container_id,omitempty"`
	ProxyContainerName string       `json:"proxy_container_name,omitempty"`
	ProxyImage         string       `json:"proxy_image,omitempty"`
	PayloadInspection  string       `json:"payload_inspection"`
	NetworkProof       string       `json:"network_proof"`
	TokenBrokerEnabled bool         `json:"token_broker_enabled"`
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
	if err := ValidateModelProviderAllowlist(req.Allowlist); err != nil {
		return EgressProxyHandle{}, err
	}
	return EgressProxyHandle{
		ProxyURL:           p.ProxyURL,
		ReceiptRef:         p.ReceiptRef,
		Allowlist:          append([]string{}, req.Allowlist...),
		PayloadInspection:  payloadInspection(req.PayloadInspection),
		NetworkProof:       networkProof(req.NetworkProof),
		TokenBrokerEnabled: req.TokenBrokerEnabled,
	}, nil
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

func payloadInspection(value string) string {
	if strings.TrimSpace(value) == "" {
		return "opaque_connect"
	}
	return strings.TrimSpace(value)
}

func networkProof(value string) string {
	if strings.TrimSpace(value) == "" {
		return "destination_allowlist_only"
	}
	return strings.TrimSpace(value)
}

func ValidateModelProviderAllowlist(allowlist []string) error {
	return modelproviders.ValidateAllowlist(allowlist)
}

func ValidateOpenRouterAllowlist(allowlist []string) error {
	return ValidateModelProviderAllowlist(allowlist)
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
