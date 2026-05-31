package contracts

import "strings"

var validEUAIActTimelineStatuses = map[string]struct{}{
	"FINAL":               {},
	"PROPOSED":            {},
	"POLITICAL_AGREEMENT": {},
	"UNCERTAIN":           {},
}

// ValidateEUAIActEvidenceProfile returns evidence-profile defects. A nil profile
// is valid for legacy packs; once present, the profile must be internally
// complete enough for offline verification of high-risk evidence posture.
func ValidateEUAIActEvidenceProfile(profile *EUAIActEvidenceProfile) []string {
	if profile == nil {
		return nil
	}

	var issues []string
	requireString(&issues, profile.ProfileID, "eu_ai_act_profile.profile_id is required")
	requireString(&issues, profile.RiskCategory, "eu_ai_act_profile.risk_category is required")
	requireString(&issues, profile.ProviderOrDeployerRole, "eu_ai_act_profile.provider_or_deployer_role is required")
	requireStrings(&issues, profile.RelevantArticles, "eu_ai_act_profile.relevant_articles is required")
	requireString(&issues, profile.RedactionProfile, "eu_ai_act_profile.redaction_profile is required")
	requireString(&issues, profile.TimelineStatus, "eu_ai_act_profile.timeline_status is required")

	if profile.TimelineStatus != "" {
		if _, ok := validEUAIActTimelineStatuses[strings.ToUpper(profile.TimelineStatus)]; !ok {
			issues = append(issues, "eu_ai_act_profile.timeline_status must be FINAL, PROPOSED, POLITICAL_AGREEMENT, or UNCERTAIN")
		}
	}

	if profile.RoleMap.Provider == "" && profile.RoleMap.Deployer == "" &&
		profile.RoleMap.Importer == "" && profile.RoleMap.Distributor == "" &&
		profile.RoleMap.ProductManufacturer == "" && profile.RoleMap.Operator == "" {
		issues = append(issues, "eu_ai_act_profile.role_map must name at least one operator role")
	}

	if euAIActProfileIsHighRisk(profile) {
		requireStrings(&issues, profile.RiskManagementRefs, "eu_ai_act_profile.risk_management_refs is required for high-risk profiles")
		requireStrings(&issues, profile.DataGovernanceRefs, "eu_ai_act_profile.data_governance_refs is required for high-risk profiles")
		requireStrings(&issues, profile.LogRecordRefs, "eu_ai_act_profile.log_record_refs is required for high-risk profiles")
		requireStrings(&issues, profile.TransparencyNoticeRefs, "eu_ai_act_profile.transparency_notice_refs is required for high-risk profiles")
		requireStrings(&issues, profile.HumanOversightRefs, "eu_ai_act_profile.human_oversight_refs is required for high-risk profiles")
		requireStrings(&issues, profile.AccuracyRobustnessCybersecurityRefs, "eu_ai_act_profile.accuracy_robustness_cybersecurity_refs is required for high-risk profiles")
		requireStrings(&issues, profile.RegistrationRefs, "eu_ai_act_profile.registration_refs is required for high-risk profiles")
	}

	if euAIActProfileIsProvider(profile) && euAIActProfileIsHighRisk(profile) {
		requireStrings(&issues, profile.TechnicalDocumentationRefs, "eu_ai_act_profile.technical_documentation_refs is required for high-risk provider profiles")
	}

	if euAIActProfileIsDeployer(profile) && euAIActProfileIsHighRisk(profile) {
		requireStrings(&issues, profile.FRIARefs, "eu_ai_act_profile.fria_refs is required for high-risk deployer profiles")
		requireStrings(&issues, profile.AffectedPersonNoticeRefs, "eu_ai_act_profile.affected_person_notice_refs is required for high-risk deployer profiles")
	}

	if len(profile.IncidentRefs) > 0 && len(profile.CorrectiveActionRefs) == 0 {
		issues = append(issues, "eu_ai_act_profile.corrective_action_refs is required when incident_refs are present")
	}

	for key, value := range profile.RedactionMetadata {
		if looksLikeRawSecret(key) {
			issues = append(issues, "eu_ai_act_profile.redaction_metadata must not include raw secret-bearing keys")
			break
		}
		if looksLikeRawSecret(value) {
			issues = append(issues, "eu_ai_act_profile.redaction_metadata must not include raw secret-bearing values")
			break
		}
	}

	return issues
}

func requireString(issues *[]string, value, message string) {
	if strings.TrimSpace(value) == "" {
		*issues = append(*issues, message)
	}
}

func requireStrings(issues *[]string, values []string, message string) {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return
		}
	}
	*issues = append(*issues, message)
}

func euAIActProfileIsHighRisk(profile *EUAIActEvidenceProfile) bool {
	text := strings.ToLower(strings.Join(append([]string{profile.RiskCategory}, profile.HighRiskReasons...), " "))
	return strings.Contains(text, "high-risk") ||
		strings.Contains(text, "annex iii") ||
		strings.Contains(text, "employment") ||
		strings.Contains(text, "worker management") ||
		strings.Contains(text, "creditworthiness") ||
		strings.Contains(text, "insurance") ||
		strings.Contains(text, "essential service") ||
		strings.Contains(text, "education") ||
		strings.Contains(text, "migration") ||
		strings.Contains(text, "law enforcement") ||
		strings.Contains(text, "justice") ||
		strings.Contains(text, "biometric") ||
		strings.Contains(text, "critical infrastructure")
}

func euAIActProfileIsProvider(profile *EUAIActEvidenceProfile) bool {
	role := strings.ToLower(strings.TrimSpace(profile.ProviderOrDeployerRole))
	return role == "provider" || profile.RoleMap.Provider != ""
}

func euAIActProfileIsDeployer(profile *EUAIActEvidenceProfile) bool {
	role := strings.ToLower(strings.TrimSpace(profile.ProviderOrDeployerRole))
	return role == "deployer" || profile.RoleMap.Deployer != ""
}

func looksLikeRawSecret(value string) bool {
	text := strings.ToLower(strings.TrimSpace(value))
	for _, token := range []string{"password", "passwd", "secret", "api_key", "apikey", "access_token", "refresh_token", "private_key"} {
		if strings.Contains(text, token) {
			return true
		}
	}
	return false
}
