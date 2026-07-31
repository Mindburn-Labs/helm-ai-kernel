package main

import "strings"

var (
	version                           = "0.0.0-dev"
	commit                            = "unknown"
	buildTime                         = "unknown"
	consoleLocalSidecarManifestSHA256 = ""
)

func displayVersion() string {
	v := version
	if v == "" {
		v = "0.0.0-dev"
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
