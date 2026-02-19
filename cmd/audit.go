package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/phoqe/safeup/internal/modules"
	"github.com/phoqe/safeup/internal/system"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Scan system for security concerns (no config required)",
	RunE:  runAudit,
}

func init() {
	rootCmd.AddCommand(auditCmd)
}

type auditCheck struct {
	category string
	name     string
	status   int
	detail   string
}

const (
	auditPass = iota
	auditWarn
	auditFail
)

func runAudit(cmd *cobra.Command, args []string) error {
	if err := system.RequireRoot(); err != nil {
		return err
	}

	osInfo, err := system.DetectOS()
	if err != nil {
		return err
	}

	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212"))
	subtitleStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	catStyle := lipgloss.NewStyle().Bold(true)
	passStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	failStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	warnStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("11"))

	fmt.Println()
	fmt.Println(titleStyle.Render("  SafeUp Audit"))
	fmt.Println(subtitleStyle.Render("  " + osInfo.PrettyName))
	fmt.Println()

	var checks []auditCheck

	checks = append(checks, auditSSH()...)
	checks = append(checks, auditUFW()...)
	checks = append(checks, auditFail2Ban()...)
	checks = append(checks, auditUpgrades()...)
	checks = append(checks, auditSysctl()...)
	checks = append(checks, auditAppArmor()...)
	checks = append(checks, auditShm()...)
	checks = append(checks, auditAuditd()...)
	checks = append(checks, auditTimesync()...)
	checks = append(checks, auditUsers()...)

	totalPass := 0
	totalWarn := 0
	totalFail := 0
	currentCat := ""

	for _, c := range checks {
		if c.category != currentCat {
			if currentCat != "" {
				fmt.Println()
			}
			currentCat = c.category
			fmt.Printf("  %s\n", catStyle.Render(currentCat))
		}

		var icon string
		switch c.status {
		case auditPass:
			totalPass++
			icon = passStyle.Render("✓")
		case auditWarn:
			totalWarn++
			icon = warnStyle.Render("⚠")
		case auditFail:
			totalFail++
			icon = failStyle.Render("✗")
		}

		if c.detail != "" {
			fmt.Printf("    %s %s — %s\n", icon, c.name, c.detail)
		} else {
			fmt.Printf("    %s %s\n", icon, c.name)
		}
	}

	fmt.Println()
	total := totalPass + totalWarn + totalFail
	if totalFail == 0 && totalWarn == 0 {
		fmt.Println(passStyle.Render(fmt.Sprintf("  All %d checks passed.", total)))
	} else {
		parts := []string{fmt.Sprintf("%d passed", totalPass)}
		if totalWarn > 0 {
			parts = append(parts, warnStyle.Render(fmt.Sprintf("%d warnings", totalWarn)))
		}
		if totalFail > 0 {
			parts = append(parts, failStyle.Render(fmt.Sprintf("%d issues", totalFail)))
		}
		fmt.Printf("  %s\n", strings.Join(parts, ", "))
	}
	fmt.Println()

	if totalFail > 0 {
		os.Exit(1)
	}

	return nil
}

func auditSSH() []auditCheck {
	var checks []auditCheck
	cat := "SSH"

	data, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		checks = append(checks, auditCheck{cat, "sshd_config readable", auditFail, "cannot read config"})
		return checks
	}
	content := string(data)

	rootLogin := getSSHValue(content, "PermitRootLogin")
	if strings.EqualFold(rootLogin, "no") {
		checks = append(checks, auditCheck{cat, "Root login disabled", auditPass, ""})
	} else if rootLogin == "" {
		checks = append(checks, auditCheck{cat, "Root login", auditFail, "not explicitly disabled (defaults to allow)"})
	} else {
		checks = append(checks, auditCheck{cat, "Root login", auditFail, "set to " + rootLogin})
	}

	passAuth := getSSHValue(content, "PasswordAuthentication")
	if strings.EqualFold(passAuth, "no") {
		checks = append(checks, auditCheck{cat, "Password auth disabled", auditPass, ""})
	} else {
		checks = append(checks, auditCheck{cat, "Password auth", auditFail, "enabled (vulnerable to brute-force)"})
	}

	port := getSSHValue(content, "Port")
	if port == "" || port == "22" {
		checks = append(checks, auditCheck{cat, "SSH port", auditWarn, "using default port 22 (high scan noise)"})
	} else {
		checks = append(checks, auditCheck{cat, "SSH port " + port, auditPass, ""})
	}

	maxAuth := getSSHValue(content, "MaxAuthTries")
	if maxAuth == "" {
		checks = append(checks, auditCheck{cat, "MaxAuthTries", auditWarn, "not set (defaults to 6)"})
	} else {
		n, err := strconv.Atoi(maxAuth)
		if err != nil {
			checks = append(checks, auditCheck{cat, "MaxAuthTries", auditWarn, "invalid value " + maxAuth})
		} else if n <= 3 {
			checks = append(checks, auditCheck{cat, "MaxAuthTries " + maxAuth, auditPass, ""})
		} else {
			checks = append(checks, auditCheck{cat, "MaxAuthTries", auditWarn, "set to " + maxAuth + " (consider 3 or lower)"})
		}
	}

	x11 := getSSHValue(content, "X11Forwarding")
	if strings.EqualFold(x11, "no") {
		checks = append(checks, auditCheck{cat, "X11Forwarding disabled", auditPass, ""})
	} else if x11 != "" {
		checks = append(checks, auditCheck{cat, "X11Forwarding", auditWarn, "set to " + x11 + " (consider no)"})
	}

	tcpFwd := getSSHValue(content, "AllowTcpForwarding")
	if strings.EqualFold(tcpFwd, "no") {
		checks = append(checks, auditCheck{cat, "AllowTcpForwarding disabled", auditPass, ""})
	} else if tcpFwd != "" {
		checks = append(checks, auditCheck{cat, "AllowTcpForwarding", auditWarn, "set to " + tcpFwd + " (consider no)"})
	}

	agentFwd := getSSHValue(content, "AllowAgentForwarding")
	if strings.EqualFold(agentFwd, "no") {
		checks = append(checks, auditCheck{cat, "AllowAgentForwarding disabled", auditPass, ""})
	} else if agentFwd != "" {
		checks = append(checks, auditCheck{cat, "AllowAgentForwarding", auditWarn, "set to " + agentFwd + " (consider no)"})
	}

	emptyPass := getSSHValue(content, "PermitEmptyPasswords")
	if strings.EqualFold(emptyPass, "no") {
		checks = append(checks, auditCheck{cat, "PermitEmptyPasswords disabled", auditPass, ""})
	} else if emptyPass != "" {
		checks = append(checks, auditCheck{cat, "PermitEmptyPasswords", auditFail, "set to " + emptyPass})
	}

	clientAlive := getSSHValue(content, "ClientAliveInterval")
	if clientAlive != "" {
		n, err := strconv.Atoi(clientAlive)
		if err == nil && n > 0 && n <= 300 {
			checks = append(checks, auditCheck{cat, "ClientAliveInterval " + clientAlive, auditPass, ""})
		} else if err == nil {
			checks = append(checks, auditCheck{cat, "ClientAliveInterval", auditWarn, "set to " + clientAlive + " (consider 300 or lower)"})
		}
	}

	clientAliveMax := getSSHValue(content, "ClientAliveCountMax")
	if clientAliveMax != "" {
		n, err := strconv.Atoi(clientAliveMax)
		if err == nil && n <= 3 {
			checks = append(checks, auditCheck{cat, "ClientAliveCountMax " + clientAliveMax, auditPass, ""})
		} else if err == nil {
			checks = append(checks, auditCheck{cat, "ClientAliveCountMax", auditWarn, "set to " + clientAliveMax + " (consider 3 or lower)"})
		}
	}

	dangerousDefaults := map[string]string{
		"PermitRootLogin":        "yes",
		"PasswordAuthentication": "yes",
		"PermitEmptyPasswords":   "yes",
	}
	dropInDir := "/etc/ssh/sshd_config.d"
	entries, readErr := os.ReadDir(dropInDir)
	if readErr == nil {
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
				continue
			}
			data, readErr := os.ReadFile(filepath.Join(dropInDir, entry.Name()))
			if readErr != nil {
				continue
			}
			dropInContent := string(data)
			for key, bad := range dangerousDefaults {
				val := getSSHValue(dropInContent, key)
				if strings.EqualFold(val, bad) {
					checks = append(checks, auditCheck{cat, entry.Name() + " overrides " + key, auditFail,
						"set to " + val + " (drop-in overrides sshd_config)"})
				}
			}
		}
	}

	return checks
}

func auditUFW() []auditCheck {
	var checks []auditCheck
	cat := "Firewall"

	if !system.IsInstalled("ufw") {
		checks = append(checks, auditCheck{cat, "UFW", auditFail, "not installed"})
		return checks
	}

	result, err := system.Run("ufw", "status")
	if err != nil {
		checks = append(checks, auditCheck{cat, "UFW", auditFail, "cannot query status"})
		return checks
	}

	if strings.Contains(result.Stdout, "Status: active") {
		checks = append(checks, auditCheck{cat, "UFW enabled", auditPass, ""})
	} else {
		checks = append(checks, auditCheck{cat, "UFW", auditFail, "installed but not enabled"})
		return checks
	}

	result, err = system.Run("ufw", "status", "verbose")
	if err == nil {
		if strings.Contains(result.Stdout, "Default: deny (incoming)") {
			checks = append(checks, auditCheck{cat, "Default deny incoming", auditPass, ""})
		} else {
			checks = append(checks, auditCheck{cat, "Default incoming policy", auditFail, "not set to deny"})
		}
	}

	return checks
}

func auditFail2Ban() []auditCheck {
	var checks []auditCheck
	cat := "Brute-force Protection"

	if !system.IsInstalled("fail2ban") {
		checks = append(checks, auditCheck{cat, "fail2ban", auditFail, "not installed"})
		return checks
	}

	if system.IsServiceActive("fail2ban") {
		checks = append(checks, auditCheck{cat, "fail2ban running", auditPass, ""})
	} else {
		checks = append(checks, auditCheck{cat, "fail2ban", auditFail, "installed but not running"})
		return checks
	}

	result, err := system.Run("fail2ban-client", "status", "sshd")
	if err == nil && result.ExitCode == 0 {
		checks = append(checks, auditCheck{cat, "SSH jail active", auditPass, ""})
	} else {
		checks = append(checks, auditCheck{cat, "SSH jail", auditWarn, "no SSH jail configured"})
	}

	data, readErr := os.ReadFile("/etc/fail2ban/jail.local")
	if readErr == nil {
		content := string(data)
		backend := extractAuditJailValue(content, "backend")
		if backend == "systemd" {
			checks = append(checks, auditCheck{cat, "backend", auditFail,
				"set to systemd — sshd child processes don't match journal filters on Ubuntu, use backend = auto with logpath"})
		} else {
			logpath := extractAuditJailValue(content, "logpath")
			if logpath != "" {
				checks = append(checks, auditCheck{cat, "logpath " + logpath, auditPass, ""})
			} else if backend == "" || backend == "auto" {
				checks = append(checks, auditCheck{cat, "logpath", auditWarn,
					"not explicitly set — ensure /var/log/auth.log is being used"})
			}
		}
	}

	return checks
}

func auditUpgrades() []auditCheck {
	var checks []auditCheck
	cat := "Automatic Updates"

	if !system.IsInstalled("unattended-upgrades") {
		checks = append(checks, auditCheck{cat, "unattended-upgrades", auditFail, "not installed"})
		return checks
	}

	checks = append(checks, auditCheck{cat, "unattended-upgrades installed", auditPass, ""})

	data, err := os.ReadFile("/etc/apt/apt.conf.d/20auto-upgrades")
	if err != nil {
		checks = append(checks, auditCheck{cat, "Auto-upgrades config", auditWarn, "config not found — may not be enabled"})
		return checks
	}

	content := string(data)
	if strings.Contains(content, `Unattended-Upgrade "1"`) {
		checks = append(checks, auditCheck{cat, "Automatic upgrades enabled", auditPass, ""})
	} else {
		checks = append(checks, auditCheck{cat, "Automatic upgrades", auditFail, "installed but not enabled"})
	}

	return checks
}

func auditSysctl() []auditCheck {
	var checks []auditCheck
	cat := "Kernel Hardening"

	for _, s := range modules.GetSysctlSettings() {
		result, err := system.Run("sysctl", "-n", s.Key)
		if err != nil || result.ExitCode != 0 {
			checks = append(checks, auditCheck{cat, s.Key, auditWarn, "cannot read"})
			continue
		}
		actual := strings.TrimSpace(result.Stdout)
		if actual == s.Value {
			checks = append(checks, auditCheck{cat, s.Key + " = " + s.Value, auditPass, ""})
		} else {
			checks = append(checks, auditCheck{cat, s.Key, auditFail, "expected " + s.Value + ", got " + actual})
		}
	}
	return checks
}

func auditAppArmor() []auditCheck {
	var checks []auditCheck
	cat := "AppArmor"

	if !system.IsInstalled("apparmor") {
		checks = append(checks, auditCheck{cat, "AppArmor", auditWarn, "not installed"})
		return checks
	}

	if system.IsServiceActive("apparmor") {
		checks = append(checks, auditCheck{cat, "AppArmor active", auditPass, ""})
	} else {
		checks = append(checks, auditCheck{cat, "AppArmor", auditFail, "installed but not active"})
	}

	statusResult, err := system.Run("aa-status", "--enabled")
	if err == nil && statusResult.ExitCode == 0 {
		checks = append(checks, auditCheck{cat, "AppArmor enabled", auditPass, ""})
	} else {
		checks = append(checks, auditCheck{cat, "AppArmor enabled", auditWarn, "not enabled"})
	}

	return checks
}

func auditShm() []auditCheck {
	var checks []auditCheck
	cat := "/dev/shm"

	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		checks = append(checks, auditCheck{cat, "mount options", auditWarn, "cannot read mounts"})
		return checks
	}

	var hasNoexec, hasNosuid, hasNodev bool
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if fields[1] == "/dev/shm" || fields[1] == "/run/shm" {
			for _, o := range strings.Split(fields[3], ",") {
				switch o {
				case "noexec":
					hasNoexec = true
				case "nosuid":
					hasNosuid = true
				case "nodev":
					hasNodev = true
				}
			}
			break
		}
	}

	if hasNoexec && hasNosuid && hasNodev {
		checks = append(checks, auditCheck{cat, "noexec,nosuid,nodev", auditPass, ""})
	} else {
		checks = append(checks, auditCheck{cat, "mount options", auditWarn,
			fmt.Sprintf("missing hardening (noexec=%v nosuid=%v nodev=%v)", hasNoexec, hasNosuid, hasNodev)})
	}

	return checks
}

func auditAuditd() []auditCheck {
	var checks []auditCheck
	cat := "auditd"

	if !system.IsInstalled("auditd") {
		checks = append(checks, auditCheck{cat, "auditd", auditWarn, "not installed"})
		return checks
	}

	if system.IsServiceActive("auditd") {
		checks = append(checks, auditCheck{cat, "auditd active", auditPass, ""})
	} else {
		checks = append(checks, auditCheck{cat, "auditd", auditWarn, "installed but not active"})
	}

	if _, err := os.Stat("/etc/audit/rules.d/safeup.rules"); err == nil {
		checks = append(checks, auditCheck{cat, "safeup rules", auditPass, ""})
	} else {
		checks = append(checks, auditCheck{cat, "safeup rules", auditWarn, "rules file not found"})
	}

	return checks
}

func auditTimesync() []auditCheck {
	var checks []auditCheck
	cat := "Time Sync"

	active := system.IsServiceActive("systemd-timesyncd") ||
		system.IsServiceActive("chrony") ||
		system.IsServiceActive("ntp")

	if active {
		checks = append(checks, auditCheck{cat, "time sync active", auditPass, ""})
	} else {
		checks = append(checks, auditCheck{cat, "time sync", auditWarn, "no timesync service active"})
	}

	return checks
}

func auditUsers() []auditCheck {
	var checks []auditCheck
	cat := "Users"

	data, err := os.ReadFile("/etc/shadow")
	if err != nil {
		checks = append(checks, auditCheck{cat, "Shadow file", auditWarn, "cannot read (need root)"})
		return checks
	}

	emptyPassUsers := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		user := parts[0]
		hash := parts[1]
		if hash == "!" || hash == "*" || hash == "!!" {
			continue
		}
		if hash == "" {
			emptyPassUsers = append(emptyPassUsers, user)
		}
	}

	if len(emptyPassUsers) > 0 {
		checks = append(checks, auditCheck{cat, "Empty passwords", auditFail,
			strings.Join(emptyPassUsers, ", ") + " have no password set"})
	} else {
		checks = append(checks, auditCheck{cat, "No empty passwords", auditPass, ""})
	}

	result, _ := system.RunShell("awk -F: '$3 == 0 && $1 != \"root\" {print $1}' /etc/passwd")
	if result != nil && result.Stdout != "" {
		checks = append(checks, auditCheck{cat, "Non-root UID 0", auditFail,
			result.Stdout + " (extra superuser accounts)"})
	} else {
		checks = append(checks, auditCheck{cat, "No extra UID 0 accounts", auditPass, ""})
	}

	return checks
}

func getSSHValue(content, key string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 && strings.EqualFold(parts[0], key) {
			return parts[1]
		}
	}
	return ""
}

func extractAuditJailValue(content, key string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.HasPrefix(line, key) {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}
