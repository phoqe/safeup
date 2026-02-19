package system

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

type CmdResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

func Run(name string, args ...string) (*CmdResult, error) {
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result := &CmdResult{
		Stdout: strings.TrimSpace(stdout.String()),
		Stderr: strings.TrimSpace(stderr.String()),
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
			return result, nil
		}
		return result, fmt.Errorf("failed to run %s: %w", name, err)
	}

	return result, nil
}

func RunShell(command string) (*CmdResult, error) {
	return Run("bash", "-c", command)
}

func IsInstalled(pkg string) bool {
	result, err := Run("dpkg", "-s", pkg)
	if err != nil {
		return false
	}
	return result.ExitCode == 0
}

var aptUpdated bool

func AptUpdate() error {
	if aptUpdated {
		return nil
	}
	result, err := Run("apt-get", "update", "-qq")
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("apt-get update failed: %s", result.Stderr)
	}
	aptUpdated = true
	return nil
}

func AptInstall(packages ...string) error {
	if err := AptUpdate(); err != nil {
		return err
	}
	args := append([]string{"install", "-y"}, packages...)
	result, err := Run("apt-get", args...)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("apt-get install failed: %s", result.Stderr)
	}
	return nil
}

func AptUpgrade() error {
	if err := AptUpdate(); err != nil {
		return err
	}
	result, err := Run("apt-get", "upgrade", "-y")
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("apt-get upgrade failed: %s", result.Stderr)
	}
	return nil
}

func ServiceAction(service, action string) error {
	result, err := Run("systemctl", action, service)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("systemctl %s %s failed: %s", action, service, result.Stderr)
	}
	return nil
}

func IsServiceActive(service string) bool {
	result, err := Run("systemctl", "is-active", service)
	if err != nil {
		return false
	}
	return result.Stdout == "active"
}
