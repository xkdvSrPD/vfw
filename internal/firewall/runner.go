// Package firewall integrates vfw with iptables and ipset.
package firewall

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Executor runs external system commands.
type Executor interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// OSExecutor runs commands through os/exec.
type OSExecutor struct{}

// Run executes a command and returns combined stdout/stderr output.
func (OSExecutor) Run(ctx context.Context, name string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, name, args...)
	output, err := command.CombinedOutput()
	text := strings.TrimSpace(string(output))
	if err != nil {
		if text == "" {
			return "", fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
		}
		return text, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, text)
	}
	return text, nil
}
