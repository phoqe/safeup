package modules

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/phoqe/safeup/internal/system"
)

type UserModule struct{}

func (m *UserModule) Name() string        { return "Create User" }
func (m *UserModule) Description() string { return "Create non-root user with sudo and SSH key" }

func (m *UserModule) Verify(cfg *system.UserConfig) *VerifyResult {
	result := &VerifyResult{ModuleName: m.Name()}
	if cfg == nil || cfg.Username == "" {
		return result
	}

	idResult, err := system.Run("id", "-u", cfg.Username)
	if err != nil || idResult.ExitCode != 0 {
		result.Checks = append(result.Checks, Check{
			Name:   "user exists",
			Status: StatusFail,
			Actual: "user not found",
		})
		return result
	}

	result.Checks = append(result.Checks, Check{
		Name:   "user exists",
		Status: StatusPass,
		Actual: "exists",
	})

	if cfg.AuthorizedKey != "" {
		getentResult, err := system.Run("getent", "passwd", cfg.Username)
		if err != nil || getentResult.ExitCode != 0 {
			return result
		}
		homeDir := strings.Split(getentResult.Stdout, ":")[5]
		authKeysPath := filepath.Join(homeDir, ".ssh", "authorized_keys")
		data, err := os.ReadFile(authKeysPath)
		hasKey := err == nil && strings.Contains(string(data), strings.TrimSpace(cfg.AuthorizedKey))
		result.Checks = append(result.Checks, Check{
			Name:     "SSH key installed",
			Status:   boolCheck(hasKey),
			Expected: "key present",
			Actual:   ternary(hasKey, "present", "missing"),
		})
	}

	return result
}

func (m *UserModule) Apply(username, authorizedKey string) error {
	if username == "" {
		return nil
	}

	result, err := system.Run("id", "-u", username)
	if err == nil && result.ExitCode == 0 {
		return addAuthorizedKey(username, authorizedKey)
	}

	cmd := exec.Command("useradd", "-m", "-s", "/bin/bash", username)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("useradd failed: %w: %s", err, string(out))
	}

	cmd = exec.Command("usermod", "-aG", "sudo", username)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("usermod sudo failed: %w: %s", err, string(out))
	}

	return addAuthorizedKey(username, authorizedKey)
}

func addAuthorizedKey(username, pubKey string) error {
	pubKey = strings.TrimSpace(pubKey)
	if pubKey == "" {
		return nil
	}

	result, err := system.Run("getent", "passwd", username)
	if err != nil || result.ExitCode != 0 {
		return fmt.Errorf("user %s not found", username)
	}

	homeDir := strings.Split(result.Stdout, ":")[5]
	sshDir := filepath.Join(homeDir, ".ssh")
	authKeysPath := filepath.Join(sshDir, "authorized_keys")

	existing, _ := os.ReadFile(authKeysPath)
	if strings.Contains(string(existing), pubKey) {
		return nil
	}

	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("cannot create %s: %w", sshDir, err)
	}

	cmd := exec.Command("chown", "-R", username+":"+username, sshDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("chown failed: %w: %s", err, string(out))
	}

	f, err := os.OpenFile(authKeysPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("cannot open authorized_keys: %w", err)
	}
	defer f.Close()

	if _, err := fmt.Fprintf(f, "%s\n", pubKey); err != nil {
		return err
	}

	cmd = exec.Command("chown", username+":"+username, authKeysPath)
	_ = cmd.Run()

	return nil
}
