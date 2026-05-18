package runtime

func RedactSecret(value string) string {
	if value == "" {
		return ""
	}
	return "[REDACTED]"
}

func ProjectSecrets(secrets map[string]string) map[string]string {
	projected := map[string]string{}
	for key, value := range secrets {
		projected[key] = RedactSecret(value)
	}
	return projected
}
