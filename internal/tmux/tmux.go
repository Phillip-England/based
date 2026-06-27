package tmux

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"
)

type Session struct {
	Name    string
	Created string
	Windows string
}

func EnsureInstalled(ctx context.Context) error {
	if _, err := exec.LookPath("tmux"); err == nil {
		return nil
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		if _, err := exec.LookPath("brew"); err != nil {
			return errors.New("tmux is not installed and Homebrew was not found; install tmux or Homebrew, then run based again")
		}
		cmd = exec.CommandContext(ctx, "brew", "install", "tmux")
	case "linux":
		cmd = linuxInstallCommand(ctx)
	default:
		return fmt.Errorf("tmux is not installed and automatic installation is unsupported on %s", runtime.GOOS)
	}
	if cmd == nil {
		return errors.New("tmux is not installed and no supported package manager was found")
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install tmux: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func linuxInstallCommand(ctx context.Context) *exec.Cmd {
	candidates := [][]string{
		{"apt-get", "sudo", "apt-get", "update", "&&", "sudo", "apt-get", "install", "-y", "tmux"},
		{"dnf", "sudo", "dnf", "install", "-y", "tmux"},
		{"yum", "sudo", "yum", "install", "-y", "tmux"},
		{"pacman", "sudo", "pacman", "-Sy", "--noconfirm", "tmux"},
		{"apk", "sudo", "apk", "add", "tmux"},
	}
	for _, candidate := range candidates {
		if _, err := exec.LookPath(candidate[0]); err == nil {
			if candidate[0] == "apt-get" {
				return exec.CommandContext(ctx, "sh", "-c", "sudo apt-get update && sudo apt-get install -y tmux")
			}
			return exec.CommandContext(ctx, candidate[1], candidate[2:]...)
		}
	}
	return nil
}

func List(ctx context.Context) ([]Session, error) {
	cmd := exec.CommandContext(ctx, "tmux", "list-sessions", "-F", "#{session_name}\t#{session_created}\t#{session_windows}")
	out, err := cmd.CombinedOutput()
	if err != nil {
		if isNoServerOutput(string(out)) {
			return nil, nil
		}
		return nil, err
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	sessions := make([]Session, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 3 {
			continue
		}
		created := parts[1]
		if unix, err := time.ParseDuration(parts[1] + "s"); err == nil {
			created = time.Unix(int64(unix.Seconds()), 0).Format(time.RFC3339)
		}
		sessions = append(sessions, Session{Name: parts[0], Created: created, Windows: parts[2]})
	}
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].Name < sessions[j].Name })
	return sessions, nil
}

func isNoServerOutput(output string) bool {
	output = strings.ToLower(strings.TrimSpace(output))
	return strings.Contains(output, "no server running") ||
		(strings.Contains(output, "error connecting to") && strings.Contains(output, "no such file or directory"))
}

func Create(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("session name is required")
	}
	return exec.CommandContext(ctx, "tmux", "new-session", "-d", "-s", name).Run()
}

func Detach(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("session name is required")
	}
	return exec.CommandContext(ctx, "tmux", "detach-client", "-s", name).Run()
}

func AttachCommand(ctx context.Context, name string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "tmux", "attach-session", "-t", name)
	cmd.Env = terminalEnv(os.Environ())
	return cmd
}

func terminalEnv(env []string) []string {
	out := make([]string, 0, len(env)+2)
	for _, entry := range env {
		if strings.HasPrefix(entry, "TERM=") || strings.HasPrefix(entry, "COLORTERM=") {
			continue
		}
		out = append(out, entry)
	}
	return append(out, "TERM=xterm-256color", "COLORTERM=truecolor")
}
