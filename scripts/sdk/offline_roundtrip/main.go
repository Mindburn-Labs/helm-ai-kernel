package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/client"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--offline" {
		for _, expected := range []string{"ALLOW", "DENY"} {
			raw, err := os.ReadFile(os.Getenv("HELM_SDK_EVIDENCE_DIR") + "/go-" + expected + ".receipt.json")
			if err != nil {
				panic(err)
			}
			result := client.VerifyReceipt(raw, os.Getenv("HELM_TRUSTED_RECEIPT_KEY"))
			if !result.Valid || result.Verdict != expected {
				panic(fmt.Sprintf("offline: %+v", result))
			}
			var changed map[string]any
			if err := json.Unmarshal(raw, &changed); err != nil {
				panic(err)
			}
			changed["verdict"] = "TAMPERED"
			tampered, err := json.Marshal(changed)
			if err != nil {
				panic(err)
			}
			if client.VerifyReceipt(tampered, os.Getenv("HELM_TRUSTED_RECEIPT_KEY")).Valid {
				panic("tampered receipt verified")
			}
			if client.VerifyReceipt(raw, "0000000000000000000000000000000000000000000000000000000000000000").Valid {
				panic("wrong key verified")
			}
			if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"sdk": "go", "offline": true, "valid": true, "verdict": expected}); err != nil {
				panic(err)
			}
		}
		return
	}
	helm := client.New(os.Getenv("HELM_URL"))
	helm.APIKey = os.Getenv("HELM_ADMIN_API_KEY")
	helm.TenantID = "sdk-offline-tenant"
	helm.PrincipalID = "sdk-offline-principal"
	key := os.Getenv("HELM_TRUSTED_RECEIPT_KEY")
	for _, step := range []struct{ tool, effect, verdict string }{{"read-ticket", "ticket:SDK-100", "ALLOW"}, {"dangerous-shell", "system:shell", "DENY"}} {
		request := client.NewEvaluateRequest()
		request.SetTool(step.tool)
		request.SetEffectLevel(step.effect)
		request.SetSessionId("go-offline-sdk")
		decision, err := helm.EvaluateDecisionV5(*request)
		if err != nil {
			panic(err)
		}
		if decision.Verdict != step.verdict || decision.ReceiptId == "" {
			panic(fmt.Sprintf("evaluate: %+v", decision))
		}
		raw, err := helm.GetReceiptJSON(decision.ReceiptId)
		if err != nil {
			panic(err)
		}
		result := client.VerifyReceipt(raw, key)
		if !result.Valid || result.Verdict != step.verdict || result.ReceiptID != decision.ReceiptId {
			panic(fmt.Sprintf("offline: %+v", result))
		}
		if client.VerifyReceipt(raw, "0000000000000000000000000000000000000000000000000000000000000000").Valid {
			panic("wrong key verified")
		}
		if dir := os.Getenv("HELM_SDK_EVIDENCE_DIR"); dir != "" {
			if err := os.WriteFile(dir+"/go-"+step.verdict+".receipt.json", raw, 0600); err != nil {
				panic(err)
			}
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"sdk": "go", "verdict": result.Verdict, "receipt_id": result.ReceiptID, "valid": result.Valid})
	}
}
