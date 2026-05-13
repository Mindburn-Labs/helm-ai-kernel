package main

import "strings"

var (
	version   = "0.5.0"
	commit    = "unknown"
	buildTime = "unknown"
)

func displayVersion() string {
	v := version
	if v == "" {
		v = "0.5.0"
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v
}

func displayCommit() string {
	if commit != "" && commit != "unknown" {
		if len(commit) > 12 {
			return commit[:12]
		}
		return commit
	}
	return getBuildInfo()
}

func displayBuildTime() string {
	if buildTime == "" {
		return "unknown"
	}
	return buildTime
}
