package modules

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/phoqe/safeup/internal/system"
)

const jailLocalPath = "/etc/fail2ban/jail.local"

type Fail2BanModule struct{}

func (m *Fail2BanModule) Name() string        { return "fail2ban" }
func (m *Fail2BanModule) Description() string { return "Brute-force protection with fail2ban" }

func (m *Fail2BanModule) Apply(cfg *system.Fail2BanConfig) error {
	if !system.IsInstalled("fail2ban") {
		if err := system.AptInstall("fail2ban"); err != nil {
			return fmt.Errorf("failed to install fail2ban: %w", err)
		}
	}

	port := "ssh"
	if cfg.SSHPort != "" && cfg.SSHPort != "22" {
		port = cfg.SSHPort
	}
	jailConfig := fmt.Sprintf(`[sshd]
enabled = true
port = %s
filter = sshd
backend = systemd
journalmatch = _SYSTEMD_UNIT=ssh.service + _COMM=sshd
maxretry = %d
bantime = %d
findtime = 600
`, port, cfg.MaxRetry, cfg.BanTime)

	if _, err := system.BackupFile(jailLocalPath); err != nil {
		return fmt.Errorf("backup failed: %w", err)
	}

	if err := os.WriteFile(jailLocalPath, []byte(jailConfig), 0644); err != nil {
		return fmt.Errorf("cannot write jail.local: %w", err)
	}

	if err := system.ServiceAction("fail2ban", "enable"); err != nil {
		return err
	}

	return system.ServiceAction("fail2ban", "restart")
}

func (m *Fail2BanModule) Plan(cfg *system.Fail2BanConfig) []string {
	var cmds []string
	cmds = append(cmds, "apt-get install -y fail2ban")
	cmds = append(cmds, "cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.bak.*")
	port := "ssh"
	if cfg.SSHPort != "" && cfg.SSHPort != "22" {
		port = cfg.SSHPort
	}
	cmds = append(cmds, "write /etc/fail2ban/jail.local (port="+port+", maxretry="+strconv.Itoa(cfg.MaxRetry)+", bantime="+strconv.Itoa(cfg.BanTime)+")")
	cmds = append(cmds, "systemctl enable fail2ban")
	cmds = append(cmds, "systemctl restart fail2ban")
	return cmds
}

func (m *Fail2BanModule) Verify(cfg *system.Fail2BanConfig) *VerifyResult {
	result := &VerifyResult{ModuleName: m.Name()}

	active := system.IsServiceActive("fail2ban")
	result.Checks = append(result.Checks, Check{
		Name:     "service running",
		Status:   boolCheck(active),
		Expected: "active",
		Actual:   ternary(active, "active", "inactive"),
	})

	statusResult, err := system.Run("fail2ban-client", "status", "sshd")
	if err != nil {
		result.Checks = append(result.Checks, Check{
			Name:   "SSH jail active",
			Status: StatusFail,
			Actual: "cannot query fail2ban",
		})
		return result
	}

	jailActive := statusResult.ExitCode == 0
	result.Checks = append(result.Checks, Check{
		Name:     "SSH jail active",
		Status:   boolCheck(jailActive),
		Expected: "enabled",
		Actual:   ternary(jailActive, "enabled", "disabled"),
	})

	data, err := os.ReadFile(jailLocalPath)
	if err == nil {
		content := string(data)

		journalMatch := extractJailValue(content, "journalmatch")
		hasCorrectMatch := strings.Contains(journalMatch, "ssh.service")
		result.Checks = append(result.Checks, Check{
			Name:     "journalmatch (Ubuntu ssh.service)",
			Status:   boolCheck(hasCorrectMatch),
			Expected: "_SYSTEMD_UNIT=ssh.service + _COMM=sshd",
			Actual:   ternary(hasCorrectMatch, journalMatch, ternary(journalMatch == "", "not set (uses default sshd.service)", journalMatch)),
		})

		if maxRetry := extractJailValue(content, "maxretry"); maxRetry != "" {
			actual, _ := strconv.Atoi(maxRetry)
			status := StatusPass
			if actual != cfg.MaxRetry {
				status = StatusWarn
			}
			result.Checks = append(result.Checks, Check{
				Name:     "maxretry",
				Status:   status,
				Expected: strconv.Itoa(cfg.MaxRetry),
				Actual:   maxRetry,
			})
		}

		if banTime := extractJailValue(content, "bantime"); banTime != "" {
			actual, _ := strconv.Atoi(banTime)
			status := StatusPass
			if actual != cfg.BanTime {
				status = StatusWarn
			}
			result.Checks = append(result.Checks, Check{
				Name:     "bantime",
				Status:   status,
				Expected: strconv.Itoa(cfg.BanTime),
				Actual:   banTime,
			})
		}
	}

	return result
}

func extractJailValue(content, key string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, key) {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}
