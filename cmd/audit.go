package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

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
	} else if maxAuth <= "3" {
		checks = append(checks, auditCheck{cat, "MaxAuthTries " + maxAuth, auditPass, ""})
	} else {
		checks = append(checks, auditCheck{cat, "MaxAuthTries", auditWarn, "set to " + maxAuth + " (consider 3 or lower)"})
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
		if hash == "" || hash == "!" || hash == "*" || hash == "!!" {
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
