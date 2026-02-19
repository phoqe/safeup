package modules

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/phoqe/safeup/internal/system"
)

const sshdConfigPath = "/etc/ssh/sshd_config"
const sshdDropInDir = "/etc/ssh/sshd_config.d"

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
	content = setSshdOption(content, "X11Forwarding", "no")
	content = setSshdOption(content, "AllowTcpForwarding", "no")
	content = setSshdOption(content, "AllowAgentForwarding", "no")
	content = setSshdOption(content, "PermitEmptyPasswords", "no")
	content = setSshdOption(content, "ClientAliveInterval", "300")
	content = setSshdOption(content, "ClientAliveCountMax", "2")
	if cfg.AuthorizedKeyUser != "" {
		content = setSshdOption(content, "AllowUsers", cfg.AuthorizedKeyUser)
	}

	if err := os.WriteFile(sshdConfigPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("cannot write sshd_config: %w", err)
	}

	enforced := map[string]string{
		"MaxAuthTries":         "3",
		"LoginGraceTime":       "60",
		"X11Forwarding":        "no",
		"AllowTcpForwarding":   "no",
		"AllowAgentForwarding": "no",
		"PermitEmptyPasswords": "no",
		"ClientAliveInterval":  "300",
		"ClientAliveCountMax":  "2",
	}
	if cfg.DisableRootLogin {
		enforced["PermitRootLogin"] = "no"
	}
	if cfg.DisablePasswordAuth {
		enforced["PasswordAuthentication"] = "no"
	}
	if err := neutralizeSSHDropIns(enforced); err != nil {
		return fmt.Errorf("failed to fix SSH drop-in overrides: %w", err)
	}

	if cfg.AuthorizedKey != "" && cfg.AuthorizedKeyUser == "" {
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

func (m *SSHModule) Plan(cfg *system.SSHConfig) []string {
	var cmds []string
	cmds = append(cmds, "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.*")
	opts := "PermitRootLogin no, PasswordAuthentication no, MaxAuthTries 3, LoginGraceTime 60, X11Forwarding no, AllowTcpForwarding no, AllowAgentForwarding no, PermitEmptyPasswords no, ClientAliveInterval 300, ClientAliveCountMax 2"
	if cfg.AuthorizedKeyUser != "" {
		opts += ", AllowUsers " + cfg.AuthorizedKeyUser
	}
	cmds = append(cmds, "write /etc/ssh/sshd_config ("+opts+")")
	cmds = append(cmds, "fix conflicting drop-ins in /etc/ssh/sshd_config.d/")
	if cfg.AuthorizedKey != "" && cfg.AuthorizedKeyUser == "" {
		cmds = append(cmds, "mkdir -p /root/.ssh")
		cmds = append(cmds, "append to /root/.ssh/authorized_keys")
	}
	cmds = append(cmds, "sshd -t")
	cmds = append(cmds, "systemctl restart ssh")
	return cmds
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

	x11 := getSshdOption(content, "X11Forwarding")
	result.Checks = append(result.Checks, Check{
		Name:     "X11Forwarding",
		Status:   boolCheck(strings.EqualFold(x11, "no")),
		Expected: "no",
		Actual:   x11,
	})

	tcpFwd := getSshdOption(content, "AllowTcpForwarding")
	result.Checks = append(result.Checks, Check{
		Name:     "AllowTcpForwarding",
		Status:   boolCheck(strings.EqualFold(tcpFwd, "no")),
		Expected: "no",
		Actual:   tcpFwd,
	})

	agentFwd := getSshdOption(content, "AllowAgentForwarding")
	result.Checks = append(result.Checks, Check{
		Name:     "AllowAgentForwarding",
		Status:   boolCheck(strings.EqualFold(agentFwd, "no")),
		Expected: "no",
		Actual:   agentFwd,
	})

	emptyPass := getSshdOption(content, "PermitEmptyPasswords")
	result.Checks = append(result.Checks, Check{
		Name:     "PermitEmptyPasswords",
		Status:   boolCheck(strings.EqualFold(emptyPass, "no")),
		Expected: "no",
		Actual:   emptyPass,
	})

	clientAlive := getSshdOption(content, "ClientAliveInterval")
	result.Checks = append(result.Checks, Check{
		Name:     "ClientAliveInterval",
		Status:   boolCheck(clientAlive == "300"),
		Expected: "300",
		Actual:   clientAlive,
	})

	clientAliveMax := getSshdOption(content, "ClientAliveCountMax")
	result.Checks = append(result.Checks, Check{
		Name:     "ClientAliveCountMax",
		Status:   boolCheck(clientAliveMax == "2"),
		Expected: "2",
		Actual:   clientAliveMax,
	})

	if cfg.AuthorizedKeyUser != "" {
		allowUsers := getSshdOption(content, "AllowUsers")
		users := strings.Fields(allowUsers)
		found := false
		for _, u := range users {
			if u == cfg.AuthorizedKeyUser {
				found = true
				break
			}
		}
		result.Checks = append(result.Checks, Check{
			Name:     "AllowUsers",
			Status:   boolCheck(found),
			Expected: cfg.AuthorizedKeyUser,
			Actual:   allowUsers,
		})
	}

	dropInChecks := map[string]string{
		"MaxAuthTries":         "3",
		"LoginGraceTime":       "60",
		"X11Forwarding":        "no",
		"AllowTcpForwarding":   "no",
		"AllowAgentForwarding": "no",
		"PermitEmptyPasswords": "no",
		"ClientAliveInterval":  "300",
		"ClientAliveCountMax":  "2",
	}
	if cfg.DisableRootLogin {
		dropInChecks["PermitRootLogin"] = "no"
	}
	if cfg.DisablePasswordAuth {
		dropInChecks["PasswordAuthentication"] = "no"
	}
	checkDropInConflicts(result, dropInChecks)

	return result
}

func neutralizeSSHDropIns(enforced map[string]string) error {
	entries, err := os.ReadDir(sshdDropInDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("cannot read %s: %w", sshdDropInDir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}

		path := filepath.Join(sshdDropInDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		content := string(data)
		modified := false
		for key, value := range enforced {
			current := getSshdOption(content, key)
			if current != "" && !strings.EqualFold(current, value) {
				re := regexp.MustCompile(`(?m)^` + key + `\s+.*$`)
				content = re.ReplaceAllString(content, key+" "+value)
				modified = true
			}
		}

		if modified {
			if _, err := system.BackupFile(path); err != nil {
				return fmt.Errorf("backup %s failed: %w", path, err)
			}
			if err := os.WriteFile(path, []byte(content), 0644); err != nil {
				return fmt.Errorf("cannot write %s: %w", path, err)
			}
		}
	}

	return nil
}

func checkDropInConflicts(result *VerifyResult, expected map[string]string) {
	entries, err := os.ReadDir(sshdDropInDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}

		path := filepath.Join(sshdDropInDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		content := string(data)
		for key, value := range expected {
			actual := getSshdOption(content, key)
			if actual != "" && !strings.EqualFold(actual, value) {
				result.Checks = append(result.Checks, Check{
					Name:     entry.Name() + " overrides " + key,
					Status:   StatusFail,
					Expected: value,
					Actual:   actual,
				})
			}
		}
	}
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
