package main

import "strings"

var (
	version   = "0.5.10"
	commit    = "unknown"
	buildTime = "unknown"
)

func displayVersion() string {
	v := version
	if v == "" {
		v = "0.5.10"
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v
}

func displayCommit() string {
	full := sourceCommit()
	if full != "" && full != "unknown" {
		if len(full) > 12 {
			return full[:12]
		}
		return full
	}
	return full
}

func sourceCommit() string {
	if value := strings.TrimSpace(commit); value != "" && value != "unknown" {
		return value
	}
	return getBuildInfo()
}

func displayBuildTime() string {
	if buildTime == "" {
		return "unknown"
	}
	return buildTime
}
