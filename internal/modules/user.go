package modules

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/phoqe/safeup/internal/system"
)

func ListOtherUsers(excludeUsername string) ([]string, error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return listOtherUsersFromReader(f, excludeUsername)
}

func listOtherUsersFromReader(r io.Reader, excludeUsername string) ([]string, error) {
	var users []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		username := fields[0]
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		if uid >= 1000 && uid < 65534 && username != excludeUsername {
			users = append(users, username)
		}
	}
	return users, scanner.Err()
}

func RemoveOtherUsers(usernames []string) error {
	for _, u := range usernames {
		result, err := system.Run("userdel", "-r", u)
		if err != nil {
			return fmt.Errorf("userdel %s failed: %w", u, err)
		}
		if result.ExitCode != 0 && !strings.Contains(result.Stderr, "does not exist") {
			return fmt.Errorf("userdel %s failed: %s", u, result.Stderr)
		}
	}
	return nil
}

type UserModule struct{}

func (m *UserModule) Name() string        { return "Create User" }
func (m *UserModule) Description() string { return "Create non-root user with sudo and SSH key" }

func (m *UserModule) Plan(cfg *system.UserConfig) []string {
	if cfg == nil || cfg.Username == "" {
		return nil
	}
	var cmds []string
	cmds = append(cmds, "useradd -m -s /bin/bash "+cfg.Username)
	cmds = append(cmds, "usermod -aG sudo "+cfg.Username)
	if cfg.AuthorizedKey != "" {
		cmds = append(cmds, "mkdir -p /home/"+cfg.Username+"/.ssh")
		cmds = append(cmds, "append to /home/"+cfg.Username+"/.ssh/authorized_keys")
		cmds = append(cmds, "chown -R "+cfg.Username+":"+cfg.Username+" /home/"+cfg.Username+"/.ssh")
	}
	if cfg.Password != "" {
		cmds = append(cmds, "chpasswd (set password for "+cfg.Username+")")
	}
	if cfg.PasswordlessSudo {
		cmds = append(cmds, "write /etc/sudoers.d/safeup-"+cfg.Username+" '"+cfg.Username+" ALL=(ALL) NOPASSWD:ALL'")
		cmds = append(cmds, "visudo -c -f /etc/sudoers.d/safeup-"+cfg.Username)
	}
	return cmds
}

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
		cmd := exec.Command("usermod", "-aG", "sudo", username)
		_ = cmd.Run()
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

	if err := os.MkdirAll(filepath.Dir(sudoersPath), 0755); err != nil {
		return fmt.Errorf("cannot create sudoers.d: %w", err)
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
