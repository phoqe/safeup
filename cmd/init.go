package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/huh/spinner"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/phoqe/safeup/internal/modules"
	"github.com/phoqe/safeup/internal/system"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Interactively harden this server",
	RunE:  runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	if err := system.RequireRoot(); err != nil {
		return err
	}

	osInfo, err := system.DetectOS()
	if err != nil {
		return err
	}

	fmt.Print("\033[H\033[2J")

	var selectedFeatures []string

	sshCfg := system.SSHConfig{
		DisableRootLogin:    true,
		DisablePasswordAuth: true,
		Port:                "2222",
	}

	ufwCfg := system.UFWConfig{
		AllowedPorts: []string{"2222/tcp", "80/tcp", "443/tcp"},
		RateLimitSSH: true,
	}

	f2bCfg := system.Fail2BanConfig{
		MaxRetry: 3,
		BanTime:  86400,
	}

	upgCfg := system.UpgradesConfig{
		AutoReboot: false,
		RebootTime: "02:00",
	}

	sshPort := sshCfg.Port
	portsStr := strings.Join(ufwCfg.AllowedPorts, ", ")
	maxRetryStr := strconv.Itoa(f2bCfg.MaxRetry)
	banTimeStr := strconv.Itoa(f2bCfg.BanTime)

	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212"))
	subtitleStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("241"))

	banner := `
   _____ ___    ____________  ______
  / ___//   |  / ____/ ____/ / / / _ \
  \__ \/ /| | / /_  / __/  / / / / __/
 ___/ / ___ |/ __/ / /____/ /_/ / ___/
/____/_/  |_/_/   /_____/\____/_/   `

	fmt.Println(titleStyle.Render(banner))
	fmt.Println()
	fmt.Println(subtitleStyle.Render("  Interactive VPS hardening for Ubuntu"))
	fmt.Println(subtitleStyle.Render("  Detected: " + osInfo.PrettyName))
	fmt.Println()
	fmt.Println(subtitleStyle.Render("  Sensible defaults have been selected for each option."))
	fmt.Println(subtitleStyle.Render("  Feel free to adjust them to suit your setup."))
	fmt.Println()

	featureForm := huh.NewForm(
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("Select hardening features").
				Description("All are recommended. Deselect any you want to skip.").
				Options(
					huh.NewOption("SSH Hardening", "ssh").Selected(true),
					huh.NewOption("UFW Firewall", "ufw").Selected(true),
					huh.NewOption("fail2ban", "fail2ban").Selected(true),
					huh.NewOption("Unattended Upgrades", "upgrades").Selected(true),
				).
				Value(&selectedFeatures),
		),
	)

	if err := featureForm.Run(); err != nil {
		return err
	}

	if len(selectedFeatures) == 0 {
		fmt.Println("No features selected. Nothing to do.")
		return nil
	}

	var groups []*huh.Group

	if contains(selectedFeatures, "ssh") {
		groups = append(groups,
			huh.NewGroup(
				huh.NewConfirm().
					Title("Disable root login via SSH?").
					Description(
						"The root account has full system access and is the most targeted by\n"+
							"automated attacks. Disabling root login forces you to use a regular\n"+
							"user with sudo, which adds an extra layer of protection.\n\n"+
							"Default: Yes (strongly recommended)").
					Value(&sshCfg.DisableRootLogin),
			),
			huh.NewGroup(
				huh.NewConfirm().
					Title("Disable password authentication?").
					Description(
						"Password-based SSH is vulnerable to brute-force attacks. SSH keys\n"+
							"use cryptographic authentication that is virtually impossible to\n"+
							"guess. Make sure you have an SSH key configured before enabling.\n\n"+
							"Default: Yes (requires SSH key to be set up already)").
					Value(&sshCfg.DisablePasswordAuth),
			),
			huh.NewGroup(
				huh.NewInput().
					Title("SSH port").
					Description(
						"Moving SSH off port 22 dramatically reduces automated scan noise.\n"+
							"Bots overwhelmingly target port 22. This doesn't add real security\n"+
							"but cuts log spam and reduces attack surface from lazy scanners.\n\n"+
							"Default: 2222").
					Value(&sshPort).
					Validate(func(s string) error {
						port, err := strconv.Atoi(s)
						if err != nil || port < 1 || port > 65535 {
							return fmt.Errorf("enter a valid port (1-65535)")
						}
						return nil
					}),
			),
		)
	}

	if contains(selectedFeatures, "ufw") {
		groups = append(groups,
			huh.NewGroup(
				huh.NewInput().
					Title("Allowed incoming ports").
					Description(
						"UFW will block all incoming traffic by default and only allow the\n"+
							"ports listed here. You need at least your SSH port to stay connected.\n"+
							"Add 80/tcp and 443/tcp if you're running a web server.\n\n"+
							"Format: comma-separated, e.g. 2222/tcp, 80/tcp, 443/tcp").
					Value(&portsStr).
					Validate(func(s string) error {
						if strings.TrimSpace(s) == "" {
							return fmt.Errorf("at least one port is required")
						}
						return nil
					}),
			),
			huh.NewGroup(
				huh.NewConfirm().
					Title("Rate-limit SSH port?").
					Description(
						"UFW rate limiting allows max 6 connections in 30 seconds from a\n"+
							"single IP. Connections beyond that are dropped. This slows down\n"+
							"brute-force attacks without affecting normal usage.\n\n"+
							"Default: Yes").
					Value(&ufwCfg.RateLimitSSH),
			),
		)
	}

	if contains(selectedFeatures, "fail2ban") {
		groups = append(groups,
			huh.NewGroup(
				huh.NewInput().
					Title("Max retries before ban").
					Description(
						"After this many failed SSH login attempts from a single IP, fail2ban\n"+
							"will ban the IP. Lower values are more aggressive but could lock out\n"+
							"legitimate users who mistype their password.\n\n"+
							"Default: 3 (good balance between security and usability)").
					Value(&maxRetryStr).
					Validate(func(s string) error {
						n, err := strconv.Atoi(s)
						if err != nil || n < 1 {
							return fmt.Errorf("enter a positive number")
						}
						return nil
					}),
			),
			huh.NewGroup(
				huh.NewInput().
					Title("Ban time (seconds)").
					Description(
						"How long a banned IP stays blocked. Longer bans are more punishing\n"+
							"to attackers but also to anyone accidentally banned. The IP is\n"+
							"automatically unbanned after this time.\n\n"+
							"Default: 86400 (24 hours). Common values: 3600 = 1h, 86400 = 1d").
					Value(&banTimeStr).
					Validate(func(s string) error {
						n, err := strconv.Atoi(s)
						if err != nil || n < 60 {
							return fmt.Errorf("enter at least 60 seconds")
						}
						return nil
					}),
			),
		)
	}

	if contains(selectedFeatures, "upgrades") {
		groups = append(groups,
			huh.NewGroup(
				huh.NewConfirm().
					Title("Enable automatic reboot when required?").
					Description(
						"Some security updates (especially kernel patches) only take effect\n"+
							"after a reboot. Enabling this lets the system reboot automatically\n"+
							"at a scheduled time instead of running with unpatched vulnerabilities.\n\n"+
							"Default: No (you may prefer to reboot manually during maintenance)").
					Value(&upgCfg.AutoReboot),
			),
			huh.NewGroup(
				huh.NewInput().
					Title("Reboot time (HH:MM)").
					Description(
						"If auto-reboot is enabled, the system will reboot at this time when\n"+
							"a reboot is needed. Pick a low-traffic window to minimize disruption.\n\n"+
							"Default: 02:00 (2 AM server time)").
					Value(&upgCfg.RebootTime),
			),
		)
	}

	if len(groups) > 0 {
		configForm := huh.NewForm(groups...)
		if err := configForm.Run(); err != nil {
			return err
		}
	}

	sshCfg.Port = sshPort

	parsedPorts := make([]string, 0)
	for _, p := range strings.Split(portsStr, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			parsedPorts = append(parsedPorts, p)
		}
	}
	ufwCfg.AllowedPorts = parsedPorts

	f2bCfg.MaxRetry, _ = strconv.Atoi(maxRetryStr)
	f2bCfg.BanTime, _ = strconv.Atoi(banTimeStr)

	var confirm bool
	summaryLines := buildSummary(selectedFeatures, &sshCfg, &ufwCfg, &f2bCfg, &upgCfg)

	confirmForm := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("Review changes").
				Description(summaryLines),
			huh.NewConfirm().
				Title("Apply these changes?").
				Value(&confirm).
				Affirmative("Yes, harden this server").
				Negative("Cancel"),
		),
	)

	if err := confirmForm.Run(); err != nil {
		return err
	}

	if !confirm {
		fmt.Println("Cancelled. No changes were made.")
		return nil
	}

	if contains(selectedFeatures, "ufw") && sshCfg.Port != "22" {
		hasSSHPort := false
		for _, p := range ufwCfg.AllowedPorts {
			if strings.TrimSuffix(p, "/tcp") == sshCfg.Port {
				hasSSHPort = true
				break
			}
		}
		if !hasSSHPort {
			ufwCfg.AllowedPorts = append(ufwCfg.AllowedPorts, sshCfg.Port+"/tcp")
		}
	}

	type applyResult struct {
		name string
		err  error
	}

	var results []applyResult

	applyFn := func() {
		if contains(selectedFeatures, "ssh") {
			m := &modules.SSHModule{}
			results = append(results, applyResult{m.Name(), m.Apply(&sshCfg)})
		}
		if contains(selectedFeatures, "ufw") {
			m := &modules.UFWModule{}
			results = append(results, applyResult{m.Name(), m.Apply(&ufwCfg)})
		}
		if contains(selectedFeatures, "fail2ban") {
			m := &modules.Fail2BanModule{}
			results = append(results, applyResult{m.Name(), m.Apply(&f2bCfg)})
		}
		if contains(selectedFeatures, "upgrades") {
			m := &modules.UpgradesModule{}
			results = append(results, applyResult{m.Name(), m.Apply(&upgCfg)})
		}
	}

	_ = spinner.New().
		Title("Applying hardening configuration...").
		Action(applyFn).
		Run()

	savedCfg := &system.SavedConfig{}
	if contains(selectedFeatures, "ssh") {
		savedCfg.SSH = &sshCfg
	}
	if contains(selectedFeatures, "ufw") {
		savedCfg.UFW = &ufwCfg
	}
	if contains(selectedFeatures, "fail2ban") {
		savedCfg.Fail2Ban = &f2bCfg
	}
	if contains(selectedFeatures, "upgrades") {
		savedCfg.Upgrades = &upgCfg
	}

	if err := system.SaveConfig(savedCfg); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not save config to %s: %v\n", system.ConfigPath, err)
	}

	fmt.Println()
	passStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	failStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	warnStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("11"))

	allPassed := true
	for _, r := range results {
		if r.err != nil {
			fmt.Printf("  %s %s: %v\n", failStyle.Render("✗"), r.name, r.err)
			allPassed = false
		} else {
			fmt.Printf("  %s %s\n", passStyle.Render("✓"), r.name)
		}
	}

	fmt.Println()
	if allPassed {
		fmt.Println(passStyle.Render("  Server hardening complete."))
	} else {
		fmt.Println(failStyle.Render("  Some modules failed. Review the errors above."))
	}

	if contains(selectedFeatures, "ssh") {
		fmt.Println()
		fmt.Println(warnStyle.Render("  ⚠ Test SSH access in a new terminal before closing this session!"))
		if sshCfg.Port != "22" {
			fmt.Println(warnStyle.Render(fmt.Sprintf("    ssh -p %s user@host", sshCfg.Port)))
		}
	}

	fmt.Println()
	fmt.Println(subtitleStyle.Render("  Run 'safeup verify' anytime to check your configuration."))
	fmt.Println()

	return nil
}

func buildSummary(features []string, ssh *system.SSHConfig, ufw *system.UFWConfig, f2b *system.Fail2BanConfig, upg *system.UpgradesConfig) string {
	var lines []string

	if contains(features, "ssh") {
		lines = append(lines, "SSH Hardening:")
		lines = append(lines, fmt.Sprintf("  Root login: %s", ternaryStr(ssh.DisableRootLogin, "disabled", "allowed")))
		lines = append(lines, fmt.Sprintf("  Password auth: %s", ternaryStr(ssh.DisablePasswordAuth, "disabled", "allowed")))
		lines = append(lines, fmt.Sprintf("  Port: %s", ssh.Port))
		lines = append(lines, "")
	}

	if contains(features, "ufw") {
		lines = append(lines, "UFW Firewall:")
		lines = append(lines, "  Default: deny incoming, allow outgoing")
		lines = append(lines, fmt.Sprintf("  Allowed ports: %s", strings.Join(ufw.AllowedPorts, ", ")))
		lines = append(lines, fmt.Sprintf("  Rate-limit SSH: %s", ternaryStr(ufw.RateLimitSSH, "yes", "no")))
		lines = append(lines, "")
	}

	if contains(features, "fail2ban") {
		lines = append(lines, "fail2ban:")
		lines = append(lines, fmt.Sprintf("  Max retries: %d", f2b.MaxRetry))
		lines = append(lines, fmt.Sprintf("  Ban time: %d seconds", f2b.BanTime))
		lines = append(lines, "")
	}

	if contains(features, "upgrades") {
		lines = append(lines, "Unattended Upgrades:")
		lines = append(lines, fmt.Sprintf("  Auto-reboot: %s", ternaryStr(upg.AutoReboot, "yes", "no")))
		if upg.AutoReboot {
			lines = append(lines, fmt.Sprintf("  Reboot time: %s", upg.RebootTime))
		}
	}

	return strings.Join(lines, "\n")
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func ternaryStr(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}
