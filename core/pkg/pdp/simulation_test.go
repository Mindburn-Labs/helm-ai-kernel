package pdp

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"
)

// EnterpriseMockPDP simulates a real Enterprise Policy Decision Point.
type EnterpriseMockPDP struct {
	policyHash string
}

func (e *EnterpriseMockPDP) Evaluate(ctx context.Context, req *DecisionRequest) (*DecisionResponse, error) {
	allow := false
	reasonCode := "PDP_DENY"

	switch req.Action {
	case "fs_read_src", "fs_write_src", "cmd_compile", "cmd_test", "mcp_list_tools":
		allow = true
		reasonCode = ""
	case "cmd_deploy_prod", "fs_read_kubeconfig", "secret_access":
		allow = false
		reasonCode = "APPROVAL_REQUIRED"
	case "fs_read_ssh", "net_egress_untrusted", "sys_delete_root":
		allow = false
		reasonCode = "POLICY_VIOLATION"
	default:
		allow = false
		reasonCode = "PDP_DENY"
	}

	resp := &DecisionResponse{
		Allow:      allow,
		ReasonCode: reasonCode,
		PolicyRef:  "enterprise-live-v1.4",
	}

	hash, err := ComputeDecisionHash(resp)
	if err == nil {
		resp.DecisionHash = hash
	}
	return resp, nil
}

func (e *EnterpriseMockPDP) Backend() Backend {
	return Backend("enterprise-mock")
}

func (e *EnterpriseMockPDP) PolicyHash() string {
	return e.policyHash
}

func TestRunEnterpriseSimulation(t *testing.T) {
	// We simulate a fleet of 27,000 developers globally generating requests.
	// Run a high-concurrency simulation of 100,000 requests.
	const totalRequests = 100000
	const concurrency = 16

	inner := &EnterpriseMockPDP{policyHash: "sha256:enterprise-policy-rules"}

	// Enable Shadow Mode (Dry-Run)
	telemetryPDP := NewTelemetryPDP(inner, true)

	// List of realistic actions based on dev metrics:
	// - 98% safe actions
	// - 1.5% escalation actions
	// - 0.5% dangerous actions
	safeActions := []string{"fs_read_src", "fs_write_src", "cmd_compile", "cmd_test", "mcp_list_tools"}
	escalateActions := []string{"cmd_deploy_prod", "fs_read_kubeconfig", "secret_access"}
	denyActions := []string{"fs_read_ssh", "net_egress_untrusted", "sys_delete_root"}

	var wg sync.WaitGroup
	reqChan := make(chan *DecisionRequest, totalRequests)

	// Generate realistic traffic distribution
	r := rand.New(rand.NewSource(42))
	for i := 0; i < totalRequests; i++ {
		roll := r.Float64() * 100.0
		var action string
		if roll < 98.0 {
			action = safeActions[r.Intn(len(safeActions))]
		} else if roll < 99.5 {
			action = escalateActions[r.Intn(len(escalateActions))]
		} else {
			action = denyActions[r.Intn(len(denyActions))]
		}

		reqChan <- &DecisionRequest{
			Principal: fmt.Sprintf("dev-%d", r.Intn(27000)),
			Action:    action,
			Resource:  "development-workspace",
			Timestamp: time.Now(),
		}
	}
	close(reqChan)

	// Track verdicts
	var allowCount, denyShadowCount, escalateShadowCount int64
	var mu sync.Mutex

	start := time.Now()

	// Spawn parallel workers simulating concurrency
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			localAllow := int64(0)
			localDenyShadow := int64(0)
			localEscalateShadow := int64(0)

			for req := range reqChan {
				resp, err := telemetryPDP.Evaluate(context.Background(), req)
				if err != nil {
					continue
				}

				// In Shadow Mode, resp.Allow is true. We check original reason code.
				if resp.ReasonCode == "" {
					localAllow++
				} else if resp.ReasonCode == "APPROVAL_REQUIRED" {
					localEscalateShadow++
				} else {
					localDenyShadow++
				}
			}

			mu.Lock()
			allowCount += localAllow
			denyShadowCount += localDenyShadow
			escalateShadowCount += localEscalateShadow
			mu.Unlock()
		}()
	}

	wg.Wait()
	duration := time.Since(start)

	totalProcessed := allowCount + denyShadowCount + escalateShadowCount
	latencyPerRequest := duration / time.Duration(totalProcessed)

	fmt.Println("\n==================================================")
	fmt.Println("   HELM AI KERNEL ENTERPRISE SCALE SIMULATION")
	fmt.Println("==================================================")
	fmt.Printf("Total Simulated Requests : %d\n", totalProcessed)
	fmt.Printf("Concurrency Workers      : %d threads\n", concurrency)
	fmt.Printf("Total Execution Time     : %v\n", duration)
	fmt.Printf("Average Latency/Decision : %v\n", latencyPerRequest)
	fmt.Printf("Throughput               : %.2f requests/sec\n", float64(totalProcessed)/duration.Seconds())
	fmt.Println("--------------------------------------------------")
	fmt.Println("VERDICT DISTRIBUTION (Shadow Mode Active):")

	allowPercent := float64(allowCount) * 100.0 / float64(totalProcessed)
	denyPercent := float64(denyShadowCount) * 100.0 / float64(totalProcessed)
	escalatePercent := float64(escalateShadowCount) * 100.0 / float64(totalProcessed)

	fmt.Printf("  - ALLOW           : %d (%.3f%%) [Permitted immediately]\n", allowCount, allowPercent)
	fmt.Printf("  - ESCALATE_SHADOW : %d (%.3f%%) [Dry-run: Allowed, flagged for Approval]\n", escalateShadowCount, escalatePercent)
	fmt.Printf("  - DENY_SHADOW     : %d (%.3f%%) [Dry-run: Allowed, flagged as Violation]\n", denyShadowCount, denyPercent)
	fmt.Println("==================================================")
}
