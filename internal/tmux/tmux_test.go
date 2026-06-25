package tmux

import "testing"

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
