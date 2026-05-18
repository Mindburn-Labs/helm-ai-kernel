// HELM SDK Example — Go
// Shows: chat completions, denial handling, conformance.
// Run: go run main.go

package main

import (
	"fmt"
	"log"
	"os"

	helm "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go/client"
)

func main() {
	baseURL := os.Getenv("HELM_URL")
	if baseURL == "" {
		baseURL = "http://127.0.0.1:7714"
	}
	client := helm.New(baseURL)

	// 1. Chat completions (governed by HELM)
	fmt.Println("=== Chat Completions ===")
	res, err := client.ChatCompletions(helm.ChatCompletionRequest{
		Model:    "gpt-4",
		Messages: []helm.ChatCompletionRequestMessagesInner{{Role: "user", Content: "List files in /tmp"}},
	})
	if err != nil {
		if apiErr, ok := err.(*helm.HelmApiError); ok {
			fmt.Printf("Denied: %s — %s\n", apiErr.ReasonCode, apiErr.Message)
		} else {
			log.Fatal(err)
		}
	} else if len(res.Choices) > 0 {
		if message, ok := res.Choices[0].GetMessageOk(); ok {
			if content, ok := message.GetContentOk(); ok && content != nil {
				fmt.Printf("Response: %s\n", *content)
			}
		}
	}

	// 2. Export evidence
	fmt.Println("\n=== Evidence ===")
	pack, err := client.ExportEvidence("")
	if err != nil {
		fmt.Printf("Evidence error: %v\n", err)
	} else {
		fmt.Printf("Exported: %d bytes\n", len(pack))
	}

	// 3. Conformance
	fmt.Println("\n=== Conformance ===")
	conf, err := client.ConformanceRun(helm.ConformanceRequest{Level: "L2"})
	if err != nil {
		if apiErr, ok := err.(*helm.HelmApiError); ok {
			fmt.Printf("Conformance error: %s\n", apiErr.ReasonCode)
		}
	} else {
		fmt.Printf("Verdict: %s Gates: %d Failed: %d\n", conf.GetVerdict(), conf.GetGates(), conf.GetFailed())
	}

	// 4. Health
	fmt.Println("\n=== Health ===")
	health, err := client.Health()
	if err != nil {
		fmt.Printf("Health check failed: %v\n", err)
	} else {
		fmt.Printf("Status: %v\n", health)
	}
}
