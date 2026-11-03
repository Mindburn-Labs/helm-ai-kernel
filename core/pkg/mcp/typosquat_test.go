package mcp

import ()

// toolName generates a unique tool name for concurrency tests.
func toolName(idx int) string {
	names := []string{
		"file_read", "file_write", "github_push", "github_pull",
		"slack_send", "slack_recv", "db_query", "db_insert",
	}
	return names[idx%len(names)]
}
