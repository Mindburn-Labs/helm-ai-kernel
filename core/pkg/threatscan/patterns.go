package threatscan

import (
	"strings"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// ────────────────────────────────────────────────────────────────
// Pattern Matching Helpers
// ────────────────────────────────────────────────────────────────

// caseInsensitiveContains returns all span matches of the needle in haystack (case-insensitive).
func caseInsensitiveContains(haystack, needle string) []contracts.MatchedSpan {
	lower := strings.ToLower(haystack)
	needleLower := strings.ToLower(needle)
	var spans []contracts.MatchedSpan
	offset := 0
	for {
		idx := strings.Index(lower[offset:], needleLower)
		if idx < 0 {
			break
		}
		start := offset + idx
		end := start + len(needle)
		spans = append(spans, contracts.MatchedSpan{
			Start: start,
			End:   end,
			Text:  haystack[start:end],
		})
		offset = end
	}
	return spans
}

// anyMatch returns all spans where any of the needles match in the normalized input.
func anyMatch(_, normalized string, needles []string) []contracts.MatchedSpan {
	var spans []contracts.MatchedSpan
	for _, needle := range needles {
		spans = append(spans, caseInsensitiveContains(normalized, needle)...)
	}
	return spans
}

// ────────────────────────────────────────────────────────────────
// Prompt Injection Rules
// ────────────────────────────────────────────────────────────────

func promptInjectionRules() []Rule {
	patterns := []string{
		"ignore previous instructions",
		"ignore all previous",
		"disregard previous",
		"disregard your instructions",
		"forget your instructions",
		"override system prompt",
		"reveal system prompt",
		"show me your system prompt",
		"print your instructions",
		"bypass safeguards",
		"bypass safety",
		"bypass restrictions",
		"jailbreak",
		"you are now",
		"pretend you are",
		"act as if you have no restrictions",
		"enter developer mode",
		"enable developer mode",
		"ignore safety guidelines",
		"from now on you will",
		"ignore content policy",
		"do anything now",
		"simulate a conversation",
	}

	return []Rule{
		{
			ID:       "PROMPT_INJECTION_01",
			Class:    contracts.ThreatClassPromptInjection,
			Severity: contracts.ThreatSeverityHigh,
			Match: func(input, normalized string) []contracts.MatchedSpan {
				return anyMatch(input, normalized, patterns)
			},
			Notes: "Detected prompt injection phrase attempting to override agent instructions",
		},
	}
}

// ────────────────────────────────────────────────────────────────
// Command Execution Rules
// ────────────────────────────────────────────────────────────────

func commandExecutionRules() []Rule {
	shellPatterns := []string{
		"curl | bash",
		"curl |bash",
		"curl|bash",
		"| bash",
		"|bash",
		"wget | sh",
		"wget |sh",
		"wget|sh",
		"curl | sh",
		"curl |sh",
		"curl|sh",
		"| sh",
		"|sh",
		"| bash -c",
		"|bash -c",
		"bash -c \"",
		"sh -c \"",
		"eval $(",
		"eval \"$(",
		"/bin/sh -c",
		"/bin/bash -c",
		"python -c \"",
		"python3 -c \"",
		"node -e \"",
		"ruby -e \"",
		"perl -e \"",
		"powershell -c",
		"; rm -rf",
		"&& rm -rf",
		"; chmod 777",
		"&& chmod 777",
		"sudo ",
		"install -y",
		"pip install",
		"npm install -g",
		"go install",
		"cargo install",
	}

	return []Rule{
		{
			ID:       "CMD_EXEC_01",
			Class:    contracts.ThreatClassCommandExecution,
			Severity: contracts.ThreatSeverityHigh,
			Match: func(input, normalized string) []contracts.MatchedSpan {
				return anyMatch(input, normalized, shellPatterns)
			},
			Notes: "Detected command-execution bait pattern (install-and-run, pipe-to-shell, destructive commands)",
		},
	}
}

// ────────────────────────────────────────────────────────────────
// Credential/Token Exposure Rules
// ────────────────────────────────────────────────────────────────

func credentialExposureRules() []Rule {
	credPatterns := []string{
		"gh auth",
		"gh auth login",
		"gh auth token",
		"echo $GITHUB_TOKEN",
		"echo $GH_TOKEN",
		"echo $AWS_SECRET",
		"echo $API_KEY",
		"cat ~/.ssh/",
		"cat /etc/shadow",
		"printenv",
		"set | grep",
		"env | grep",
		"access_token",
		"secret_key",
		"private_key",
		".env file",
		"credentials.json",
		"service_account",
	}

	return []Rule{
		{
			ID:       "CRED_EXPOSURE_01",
			Class:    contracts.ThreatClassCredentialExposure,
			Severity: contracts.ThreatSeverityHigh,
			Match: func(input, normalized string) []contracts.MatchedSpan {
				return anyMatch(input, normalized, credPatterns)
			},
			Notes: "Detected credential exposure or token access pattern",
		},
	}
}

// ────────────────────────────────────────────────────────────────
// Software Publish Rules
// ────────────────────────────────────────────────────────────────

func softwarePublishRules() []Rule {
	publishPatterns := []string{
		"npm publish",
		"cargo publish",
		"gem push",
		"docker push",
		"twine upload",
		"pypi upload",
		"go publish",
		"helm push",
		"gh release create",
		"git push --force",
		"git push -f",
		"force push",
	}

	return []Rule{
		{
			ID:       "SOFTWARE_PUBLISH_01",
			Class:    contracts.ThreatClassSoftwarePublish,
			Severity: contracts.ThreatSeverityHigh,
			Match: func(input, normalized string) []contracts.MatchedSpan {
				return anyMatch(input, normalized, publishPatterns)
			},
			Notes: "Detected software publish or release pattern",
		},
	}
}

// ────────────────────────────────────────────────────────────────
// Suspicious Fetch / Egress Rules
// ────────────────────────────────────────────────────────────────

func suspiciousFetchRules() []Rule {
	fetchPatterns := []string{
		"curl http",
		"wget http",
		"fetch(",
		"requests.get(",
		"requests.post(",
		"http.get(",
		"axios.get(",
		"urllib.request",
		"exfiltrate",
		"exfiltration",
		"send to my server",
		"post data to",
		"upload to",
		"transfer to external",
	}

	return []Rule{
		{
			ID:       "SUSPICIOUS_FETCH_01",
			Class:    contracts.ThreatClassSuspiciousFetch,
			Severity: contracts.ThreatSeverityMedium,
			Match: func(input, normalized string) []contracts.MatchedSpan {
				return anyMatch(input, normalized, fetchPatterns)
			},
			Notes: "Detected suspicious external fetch or data egress pattern",
		},
	}
}
