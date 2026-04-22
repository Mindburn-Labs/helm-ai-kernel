package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

func init() {
	Register(Subcommand{
		Name:    "mama",
		Aliases: []string{},
		Usage:   "Control the canonical MAMA AI runtime (mission, mode, agents)",
		RunFn:   runMamaCmd,
	})
}

func runMamaCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm mama <mission|mode|agents|health>")
		return 2
	}

	subCmd := args[0]
	switch subCmd {
	case "mission", "mode", "agents", "health":
		return fetchAndPrintMAMAApi(subCmd, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "Unknown subcommand: %s\n", subCmd)
		fmt.Fprintln(stderr, "Available: mission, mode, agents, health")
		return 2
	}
}

func fetchAndPrintMAMAApi(endpoint string, stdout, stderr io.Writer) int {
	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("http://localhost:8080/api/mama/%s", endpoint)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Fprintf(stderr, "%sFailed to create request: %v%s\n", ColorRed, err, ColorReset)
		return 1
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(stderr, "%sFailed to reach HELM kernel at localhost:8080%s\n", ColorRed, ColorReset)
		fmt.Fprintf(stderr, "Is the HELM server running? (Run: %shelm server%s)\n", ColorBold, ColorReset)
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(stderr, "%sAPI Error: %s%s\n", ColorRed, resp.Status, ColorReset)
		return 1
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(stderr, "%sFailed to read response body: %v%s\n", ColorRed, err, ColorReset)
		return 1
	}

	// Pretty print the JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		// Output raw if not JSON (though the API always targets JSON)
		fmt.Fprintln(stdout, string(body))
		return 0
	}

	pretty, _ := json.MarshalIndent(parsed, "", "  ")
	fmt.Fprintf(stdout, "%s\n", pretty)
	return 0
}
