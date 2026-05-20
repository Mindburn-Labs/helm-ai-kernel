package runtime

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/receipts"
)

type DockerSidecarEgressProxy struct {
	Image      string
	DockerBin  string
	ReceiptDir string
}

func (p DockerSidecarEgressProxy) Start(req EgressProxyRequest) (EgressProxyHandle, error) {
	if strings.TrimSpace(req.LaunchID) == "" {
		return EgressProxyHandle{}, errors.New("docker egress proxy launch id is required")
	}
	if err := ValidateOpenRouterAllowlist(req.Allowlist); err != nil {
		return EgressProxyHandle{}, err
	}
	image := strings.TrimSpace(p.Image)
	if image == "" {
		return EgressProxyHandle{}, errors.New("docker egress proxy image is required")
	}
	if !strings.Contains(image, "@sha256:") {
		return EgressProxyHandle{}, errors.New("docker egress proxy image must be immutable image@sha256")
	}
	docker := strings.TrimSpace(p.DockerBin)
	if docker == "" {
		docker = "docker"
	}
	component := safeFileComponent(req.LaunchID)
	networkName := "helm-lp-" + component + "-net"
	proxyName := "helm-lp-" + component + "-proxy"
	receiptDir := strings.TrimSpace(req.ReceiptDir)
	if receiptDir == "" {
		receiptDir = strings.TrimSpace(p.ReceiptDir)
	}
	if receiptDir == "" {
		receiptDir = defaultEgressReceiptDir(req.LaunchID)
	}
	if err := os.MkdirAll(receiptDir, 0o700); err != nil {
		return EgressProxyHandle{}, fmt.Errorf("create docker egress receipt dir: %w", err)
	}

	_ = exec.Command(docker, "rm", "-f", proxyName).Run()
	_ = exec.Command(docker, "network", "rm", networkName).Run()
	if out, err := exec.Command(docker, "network", "create", "--internal", networkName).CombinedOutput(); err != nil {
		return EgressProxyHandle{}, fmt.Errorf("create launch egress network: %w: %s", err, strings.TrimSpace(string(out)))
	}
	args := []string{
		"run", "-d",
		"--name", proxyName,
		"--network", "bridge",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
		"-v", receiptDir + ":/receipts:rw",
		"-e", "HELM_EGRESS_LAUNCH_ID=" + req.LaunchID,
		"-e", "HELM_EGRESS_ALLOWLIST=" + strings.Join(req.Allowlist, ","),
		"-e", "HELM_EGRESS_RECEIPT_DIR=/receipts",
		"-e", "HELM_EGRESS_LISTEN=:8080",
		image,
	}
	out, err := exec.Command(docker, args...).CombinedOutput()
	if err != nil {
		_ = exec.Command(docker, "network", "rm", networkName).Run()
		return EgressProxyHandle{}, fmt.Errorf("start launch egress proxy sidecar: %w: %s", err, strings.TrimSpace(string(out)))
	}
	containerID := strings.TrimSpace(string(out))
	if out, err := exec.Command(docker, "network", "connect", "--alias", proxyName, networkName, proxyName).CombinedOutput(); err != nil {
		_ = exec.Command(docker, "rm", "-f", proxyName).Run()
		_ = exec.Command(docker, "network", "rm", networkName).Run()
		return EgressProxyHandle{}, fmt.Errorf("attach egress proxy to launch network: %w: %s", err, strings.TrimSpace(string(out)))
	}
	receiptRef := writeSidecarReceipt(receiptDir, req.LaunchID, "ALLOW", "docker_sidecar_started", map[string]any{
		"network_name":          networkName,
		"proxy_container_id":    containerID,
		"proxy_container_name":  proxyName,
		"proxy_image":           image,
		"raw_app_egress_denied": true,
		"payload_inspection":    payloadInspection(req.PayloadInspection),
		"network_proof":         networkProof(req.NetworkProof),
		"token_broker_enabled":  req.TokenBrokerEnabled,
	})
	return EgressProxyHandle{
		ProxyURL:           "http://" + proxyName + ":8080",
		ReceiptRef:         receiptRef,
		ReceiptDir:         receiptDir,
		Allowlist:          append([]string{}, req.Allowlist...),
		NetworkName:        networkName,
		ProxyContainerID:   containerID,
		ProxyContainerName: proxyName,
		PayloadInspection:  payloadInspection(req.PayloadInspection),
		NetworkProof:       networkProof(req.NetworkProof),
		TokenBrokerEnabled: req.TokenBrokerEnabled,
		Stop: func() error {
			var stopErr error
			if out, err := exec.Command(docker, "rm", "-f", proxyName).CombinedOutput(); err != nil {
				stopErr = fmt.Errorf("remove egress proxy sidecar: %w: %s", err, strings.TrimSpace(string(out)))
			}
			if out, err := exec.Command(docker, "network", "rm", networkName).CombinedOutput(); err != nil && stopErr == nil {
				stopErr = fmt.Errorf("remove egress network: %w: %s", err, strings.TrimSpace(string(out)))
			}
			_ = writeSidecarReceipt(receiptDir, req.LaunchID, "ALLOW", "docker_sidecar_stopped", map[string]any{
				"network_name":         networkName,
				"proxy_container_name": proxyName,
			})
			return stopErr
		},
	}, nil
}

func writeSidecarReceipt(dir, launchID, verdict, reason string, subject map[string]any) string {
	if subject == nil {
		subject = map[string]any{}
	}
	subject["reason"] = reason
	receipt := receipts.NewReceipt("launchpad.egress_proxy", launchID, verdict, subject)
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return receipt.ReceiptID
	}
	path := filepath.Join(dir, safeFileComponent(receipt.Hash)+"-"+time.Now().UTC().Format("20060102T150405Z")+".json")
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return receipt.ReceiptID
	}
	return receipt.ReceiptID
}
