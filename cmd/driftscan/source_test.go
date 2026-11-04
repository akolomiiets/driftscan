package main

import (
	"path/filepath"
	"testing"
)

func TestSourceFromEnv(t *testing.T) {
	ws := t.TempDir()
	tests := []struct {
		name       string
		dir        string
		env        map[string]string
		wantPrefix string
		wantBlob   string
	}{
		{"subdir", filepath.Join(ws, "infra"), map[string]string{"GITHUB_WORKSPACE": ws, "GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "o/r", "GITHUB_SHA": "abc"}, "infra", "https://github.com/o/r/blob/abc"},
		{"workspace root", ws, map[string]string{"GITHUB_WORKSPACE": ws, "GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "o/r", "GITHUB_SHA": "abc"}, "", "https://github.com/o/r/blob/abc"},
		{"outside workspace", t.TempDir(), map[string]string{"GITHUB_WORKSPACE": ws}, "", ""},
		{"no workspace", filepath.Join(ws, "infra"), map[string]string{}, "", ""},
		{"missing sha", ws, map[string]string{"GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "o/r"}, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, k := range []string{"GITHUB_WORKSPACE", "GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "GITHUB_SHA"} {
				t.Setenv(k, tt.env[k])
			}

			got := sourceFromEnv(tt.dir)

			if got.Prefix != tt.wantPrefix || got.BlobURL != tt.wantBlob {
				t.Errorf("got %+v, want prefix %q blob %q", got, tt.wantPrefix, tt.wantBlob)
			}
		})
	}
}
