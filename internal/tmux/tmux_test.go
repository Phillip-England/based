package tmux

import (
	"strings"
	"testing"
)

func TestIsNoServerOutput(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{
			name:   "linux no server",
			output: "no server running on /tmp/tmux-501/default",
			want:   true,
		},
		{
			name:   "macos missing socket",
			output: "error connecting to /private/tmp/tmux-501/default (No such file or directory)",
			want:   true,
		},
		{
			name:   "real error",
			output: "can't find session: missing",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNoServerOutput(tt.output); got != tt.want {
				t.Fatalf("isNoServerOutput(%q) = %v, want %v", tt.output, got, tt.want)
			}
		})
	}
}

func TestTerminalEnvUsesBrowserCompatibleTerminal(t *testing.T) {
	got := terminalEnv([]string{
		"PATH=/usr/bin",
		"TERM=dumb",
		"COLORTERM=old",
		"HOME=/tmp/based",
	})

	if joined := "\n" + strings.Join(got, "\n") + "\n"; strings.Contains(joined, "\nTERM=dumb\n") {
		t.Fatalf("terminalEnv kept unsupported TERM: %q", got)
	}

	want := map[string]bool{
		"PATH=/usr/bin":       false,
		"HOME=/tmp/based":     false,
		"TERM=xterm-256color": false,
		"COLORTERM=truecolor": false,
	}
	for _, entry := range got {
		if _, ok := want[entry]; ok {
			want[entry] = true
		}
	}
	for entry, found := range want {
		if !found {
			t.Fatalf("terminalEnv missing %s in %q", entry, got)
		}
	}
}
