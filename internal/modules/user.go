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

	if cfg.PasswordlessSudo {
		sudoersPath := "/etc/sudoers.d/safeup-" + cfg.Username
		data, err := os.ReadFile(sudoersPath)
		hasNopasswd := err == nil && strings.Contains(string(data), "NOPASSWD")
		result.Checks = append(result.Checks, Check{
			Name:     "passwordless sudo",
			Status:   boolCheck(hasNopasswd),
			Expected: "configured",
			Actual:   ternary(hasNopasswd, "configured", "missing"),
		})
	}

	return result
}

func (m *UserModule) Apply(cfg *system.UserConfig) error {
	if cfg == nil || cfg.Username == "" {
		return nil
	}

	username := cfg.Username
	authorizedKey := cfg.AuthorizedKey

	result, err := system.Run("id", "-u", username)
	if err == nil && result.ExitCode == 0 {
		if err := addAuthorizedKey(username, authorizedKey); err != nil {
			return err
		}
		if err := setPassword(username, cfg.Password); err != nil {
			return err
		}
		return configureSudo(cfg)
	}

	cmd := exec.Command("useradd", "-m", "-s", "/bin/bash", username)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("useradd failed: %w: %s", err, string(out))
	}

	cmd = exec.Command("usermod", "-aG", "sudo", username)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("usermod sudo failed: %w: %s", err, string(out))
	}

	if err := addAuthorizedKey(username, authorizedKey); err != nil {
		return err
	}

	if err := setPassword(username, cfg.Password); err != nil {
		return err
	}

	return configureSudo(cfg)
}

func setPassword(username, password string) error {
	password = strings.TrimSpace(password)
	if password == "" {
		return nil
	}

	cmd := exec.Command("chpasswd")
	cmd.Stdin = strings.NewReader(username + ":" + password + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("chpasswd failed: %w: %s", err, string(out))
	}
	return nil
}

func configureSudo(cfg *system.UserConfig) error {
	sudoersPath := "/etc/sudoers.d/safeup-" + cfg.Username
	if !cfg.PasswordlessSudo {
		os.Remove(sudoersPath)
		return nil
	}

	content := cfg.Username + " ALL=(ALL) NOPASSWD:ALL\n"

	if err := os.WriteFile(sudoersPath, []byte(content), 0440); err != nil {
		return fmt.Errorf("cannot write sudoers: %w", err)
	}

	result, err := system.Run("visudo", "-c", "-f", sudoersPath)
	if err != nil {
		os.Remove(sudoersPath)
		return fmt.Errorf("visudo check failed: %w", err)
	}
	if result.ExitCode != 0 {
		os.Remove(sudoersPath)
		return fmt.Errorf("invalid sudoers: %s", result.Stderr)
	}

	return nil
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
