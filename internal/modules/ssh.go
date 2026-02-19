package modules

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/phoqe/safeup/internal/system"
)

const sshdConfigPath = "/etc/ssh/sshd_config"

type SSHModule struct{}

func (m *SSHModule) Name() string        { return "SSH Hardening" }
func (m *SSHModule) Description() string { return "Harden SSH daemon configuration" }

func (m *SSHModule) Apply(cfg *system.SSHConfig) error {
	if _, err := system.BackupFile(sshdConfigPath); err != nil {
		return fmt.Errorf("backup failed: %w", err)
	}

	data, err := os.ReadFile(sshdConfigPath)
	if err != nil {
		return fmt.Errorf("cannot read sshd_config: %w", err)
	}

	content := string(data)

	if cfg.DisableRootLogin {
		content = setSshdOption(content, "PermitRootLogin", "no")
	}
	if cfg.DisablePasswordAuth {
		content = setSshdOption(content, "PasswordAuthentication", "no")
	}
	if cfg.Port != "" && cfg.Port != "22" {
		content = setSshdOption(content, "Port", cfg.Port)
	}

	content = setSshdOption(content, "MaxAuthTries", "3")
	content = setSshdOption(content, "LoginGraceTime", "60")

	if err := os.WriteFile(sshdConfigPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("cannot write sshd_config: %w", err)
	}

	if cfg.AuthorizedKey != "" {
		if err := installAuthorizedKey(cfg.AuthorizedKey); err != nil {
			return fmt.Errorf("failed to install SSH key: %w", err)
		}
	}

	result, err := system.Run("sshd", "-t")
	if err != nil {
		return fmt.Errorf("sshd config test failed: %w", err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("sshd config is invalid: %s", result.Stderr)
	}

	return system.ServiceAction("ssh", "restart")
}

func installAuthorizedKey(pubKey string) error {
	pubKey = strings.TrimSpace(pubKey)
	if pubKey == "" {
		return nil
	}

	sshDir := "/root/.ssh"
	authKeysPath := sshDir + "/authorized_keys"

	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("cannot create %s: %w", sshDir, err)
	}

	existing, _ := os.ReadFile(authKeysPath)
	if strings.Contains(string(existing), pubKey) {
		return nil
	}

	f, err := os.OpenFile(authKeysPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("cannot open authorized_keys: %w", err)
	}
	defer f.Close()

	_, err = fmt.Fprintf(f, "%s\n", pubKey)
	return err
}

func (m *SSHModule) Verify(cfg *system.SSHConfig) *VerifyResult {
	result := &VerifyResult{ModuleName: m.Name()}

	data, err := os.ReadFile(sshdConfigPath)
	if err != nil {
		result.Checks = append(result.Checks, Check{
			Name:   "config readable",
			Status: StatusFail,
			Actual: err.Error(),
		})
		return result
	}

	content := string(data)

	if cfg.DisableRootLogin {
		val := getSshdOption(content, "PermitRootLogin")
		result.Checks = append(result.Checks, Check{
			Name:     "root login disabled",
			Status:   boolCheck(strings.EqualFold(val, "no")),
			Expected: "no",
			Actual:   val,
		})
	}

	if cfg.DisablePasswordAuth {
		val := getSshdOption(content, "PasswordAuthentication")
		result.Checks = append(result.Checks, Check{
			Name:     "password auth disabled",
			Status:   boolCheck(strings.EqualFold(val, "no")),
			Expected: "no",
			Actual:   val,
		})
	}

	if cfg.Port != "" {
		val := getSshdOption(content, "Port")
		if val == "" {
			val = "22"
		}
		result.Checks = append(result.Checks, Check{
			Name:     "port",
			Status:   boolCheck(val == cfg.Port),
			Expected: cfg.Port,
			Actual:   val,
		})
	}

	maxAuth := getSshdOption(content, "MaxAuthTries")
	result.Checks = append(result.Checks, Check{
		Name:     "MaxAuthTries",
		Status:   boolCheck(maxAuth == "3"),
		Expected: "3",
		Actual:   maxAuth,
	})

	return result
}

func setSshdOption(content, key, value string) string {
	re := regexp.MustCompile(`(?m)^#?\s*` + key + `\s+.*$`)
	replacement := key + " " + value
	if re.MatchString(content) {
		return re.ReplaceAllString(content, replacement)
	}
	return content + "\n" + replacement + "\n"
}

func getSshdOption(content, key string) string {
	re := regexp.MustCompile(`(?m)^` + key + `\s+(.+)$`)
	matches := re.FindStringSubmatch(content)
	if len(matches) >= 2 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

func boolCheck(ok bool) CheckStatus {
	if ok {
		return StatusPass
	}
	return StatusFail
}
