package main

import (
	"os"
	"testing"
)

// onGitHubActions records whether the tests run on a GitHub Actions runner, before TestMain clears
// the environment.
var onGitHubActions bool

// TestMain clears the GitHub Actions environment so tests behave the same on a runner as locally;
// tests that need these variables set them with t.Setenv.
func TestMain(m *testing.M) {
	onGitHubActions = os.Getenv("GITHUB_ACTIONS") == "true"
	for _, k := range []string{
		"GITHUB_ACTIONS", "GITHUB_WORKSPACE", "GITHUB_SERVER_URL", "GITHUB_REPOSITORY",
		"GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_STEP_SUMMARY",
	} {
		os.Unsetenv(k)
	}
	os.Exit(m.Run())
}
