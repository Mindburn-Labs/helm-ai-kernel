package install

import "strings"

func SourceInstallAllowed(defaultPath bool, command string) bool {
	if defaultPath {
		return false
	}
	disallowed := []string{"git pull", "git stash", "git stash apply", "npm install", "pnpm install", "yarn install"}
	lower := strings.ToLower(command)
	for _, token := range disallowed {
		if strings.Contains(lower, token) {
			return false
		}
	}
	return true
}
