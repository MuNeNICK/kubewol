package utils

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	defaultKindBinary  = "kind"
	defaultKindCluster = "kind"
)

// Run executes a command from the project root and returns its combined output.
func Run(cmd *exec.Cmd) (string, error) {
	dir, err := GetProjectDir()
	if err != nil {
		return "", err
	}
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GO111MODULE=on")
	command := strings.Join(cmd.Args, " ")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("%q failed with output %q: %w", command, string(output), err)
	}
	return string(output), nil
}

// LoadImageToKindClusterWithName loads a local Docker image into the target kind cluster.
func LoadImageToKindClusterWithName(name string) error {
	cluster := defaultKindCluster
	if v, ok := os.LookupEnv("KIND_CLUSTER"); ok {
		cluster = v
	}
	kindBinary := defaultKindBinary
	if v, ok := os.LookupEnv("KIND"); ok {
		kindBinary = v
	}
	cmd := exec.Command(kindBinary, "load", "docker-image", name, "--name", cluster)
	_, err := Run(cmd)
	return err
}

// GetNonEmptyLines splits command output into non-empty lines.
func GetNonEmptyLines(output string) []string {
	lines := strings.Split(output, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// GetProjectDir walks up from the current directory until it finds the repo root.
func GetProjectDir() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getwd: %w", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not locate project root from %q", dir)
		}
		dir = parent
	}
}
