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

var (
	dimStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	checkStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	valueStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("15"))
	stepStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("212"))
	warnStyle     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("11"))
	dividerStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("237"))
)

func wizardTheme() *huh.Theme {
	t := huh.ThemeCharm()
	t.Focused.Base = lipgloss.NewStyle().PaddingLeft(2)
	t.Blurred.Base = lipgloss.NewStyle().PaddingLeft(2)
	t.Focused.Title = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "#1a1a2e", Dark: "#f8f8f2"})
	t.Focused.Description = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	return t
}

func renderHeader(current, total int, answered []answeredStep) {
	fmt.Print("\033[H\033[2J")

	if total > 0 {
		fmt.Printf("  %s\n", stepStyle.Render(fmt.Sprintf("Step %d of %d", current, total)))
	}

	if len(answered) > 0 {
		fmt.Println()
		fmt.Println(dividerStyle.Render("  " + strings.Repeat("─", 40)))

		currentSection := ""
		for _, a := range answered {
			if a.section != currentSection {
				currentSection = a.section
				fmt.Printf("\n  %s\n", dimStyle.Render(currentSection))
			}
			fmt.Printf("    %s  %s  %s\n",
				checkStyle.Render("✓"),
				dimStyle.Render(a.label),
				valueStyle.Render(a.val),
			)
		}

		fmt.Println()
		fmt.Println(dividerStyle.Render("  " + strings.Repeat("─", 40)))
	}

	fmt.Println()
}

type answeredStep struct {
	section string
	label   string
	val     string
}

func runForm(f huh.Field) error {
	return huh.NewForm(huh.NewGroup(f)).WithTheme(wizardTheme()).Run()
}

func formatPlan(cmds []string) string {
	if len(cmds) == 0 {
		return ""
	}
	return "\n\nCommands:\n  " + strings.Join(cmds, "\n  ")
}

func runInit(cmd *cobra.Command, args []string) error {
	var err error

	if !DryRun {
		if err = system.RequireRoot(); err != nil {
			return err
		}
	}

	if !DryRun {
		_, err = system.DetectOS()
		if err != nil {
			return err
		}
	}

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

	upgCfg := system.UpgradesConfig{}
	sysctlCfg := system.SysctlConfig{}
	apparmorCfg := system.AppArmorConfig{}
	shmCfg := system.ShmConfig{}
	auditdCfg := system.AuditdConfig{}
	timesyncCfg := system.TimesyncConfig{}

	userCfg := system.UserConfig{}
	userName := ""
	userPassword := ""
	var otherUsers []string
	removeOtherUsers := false
	sshPort := sshCfg.Port
	portsStr := strings.Join(ufwCfg.AllowedPorts, ", ")
	maxRetryStr := strconv.Itoa(f2bCfg.MaxRetry)
	banTimeStr := strconv.Itoa(f2bCfg.BanTime)
	addSSHKey := true
	sshKey := ""

	renderHeader(0, 0, nil)

	err = huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("Welcome to SafeUp").
				Description(
					"This wizard will harden your Ubuntu server step by step.\n\n"+
						"Sensible defaults have been pre-selected.\n"+
						"Feel free to adjust any value to suit your setup.").
				Next(true).
				NextLabel("Get started →"),
		),
		huh.NewGroup(
			huh.NewNote().
				Title("Update package lists").
				Description(
					"Press Enter to run apt-get update. This refreshes the package index\n"+
						"before installing any hardening components.").
				Next(true).
				NextLabel("Enter"),
		),
	).WithTheme(wizardTheme()).Run()
	if err != nil {
		return err
	}

	if !DryRun {
		if err = system.AptUpdate(); err != nil {
			return fmt.Errorf("apt update failed: %w", err)
		}
	}

	renderHeader(0, 0, nil)

	err = huh.NewForm(
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("Select hardening features").
				Description("All are recommended. Deselect any you want to skip.").
				Options(
					huh.NewOption("Create User", "user").Selected(true),
					huh.NewOption("SSH Hardening", "ssh").Selected(true),
					huh.NewOption("UFW Firewall", "ufw").Selected(true),
					huh.NewOption("fail2ban", "fail2ban").Selected(true),
					huh.NewOption("Kernel Hardening", "sysctl").Selected(true),
					huh.NewOption("AppArmor", "apparmor").Selected(true),
					huh.NewOption("/dev/shm Hardening", "shm").Selected(true),
					huh.NewOption("auditd", "auditd").Selected(true),
					huh.NewOption("Time Sync", "timesync").Selected(true),
					huh.NewOption("Unattended Upgrades", "upgrades").Selected(true),
				).
				Value(&selectedFeatures),
		),
	).WithTheme(wizardTheme()).Run()
	if err != nil {
		return err
	}

	if len(selectedFeatures) == 0 {
		fmt.Println("No features selected. Nothing to do.")
		return nil
	}

	type wizardStep struct {
		section string
		label   string
		field   huh.Field
		fieldFn func() huh.Field
		value   func() string
	}

	var steps []wizardStep

	if contains(selectedFeatures, "user") {
		steps = append(steps,
			wizardStep{
				section: "Create User",
				label:   "Username",
				fieldFn: func() huh.Field {
					u := userName
					if u == "" {
						u = "<username>"
					}
					cmds := (&modules.UserModule{}).Plan(&system.UserConfig{Username: u, AuthorizedKey: sshKey})
					return huh.NewInput().
						Title("Username for new user").
						Description(
							"Create a non-root user with sudo access. You will use this user\n"+
								"instead of root for SSH. Required when disabling root login.\n\n"+
								"Use lowercase letters, numbers, hyphens only."+
								formatPlan(cmds)).
						Value(&userName).
						Validate(func(s string) error {
							s = strings.TrimSpace(s)
							if s == "" {
								return fmt.Errorf("username cannot be empty")
							}
							if s == "root" {
								return fmt.Errorf("cannot create user named root")
							}
							for _, c := range s {
								if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
									continue
								}
								return fmt.Errorf("use only lowercase letters, numbers, hyphens, underscores")
							}
							return nil
						})
				},
				value: func() string { return userName },
			},
			wizardStep{
				section: "Create User",
				label:   "SSH public key",
				fieldFn: func() huh.Field {
					cmds := (&modules.UserModule{}).Plan(&system.UserConfig{Username: userName, AuthorizedKey: sshKey})
					return huh.NewText().
						Title("Paste your SSH public key").
						Description(
							"Paste the contents of your public key (e.g. ~/.ssh/id_ed25519.pub).\n"+
								"It starts with 'ssh-ed25519', 'ssh-rsa', or similar.\n\n"+
								"This will be added to the new user's authorized_keys."+
								formatPlan(cmds)).
						Value(&sshKey).
						Validate(func(s string) error {
							s = strings.TrimSpace(s)
							if s == "" {
								return fmt.Errorf("key cannot be empty")
							}
							if !strings.HasPrefix(s, "ssh-") && !strings.HasPrefix(s, "ecdsa-") {
								return fmt.Errorf("doesn't look like a public key (should start with ssh- or ecdsa-)")
							}
							return nil
						})
				},
				value: func() string { return sshKey[:min(30, len(sshKey))] + "…" },
			},
			wizardStep{
				section: "Create User",
				label:   "Password for sudo",
				fieldFn: func() huh.Field {
					return huh.NewInput().
						Title("Password for sudo").
						Description(
							"Sudo will require this password. This prevents instant root access\n"+
								"if the SSH key is ever compromised.").
						Value(&userPassword).
						Password(true).
						Validate(func(s string) error {
							if strings.TrimSpace(s) == "" {
								return fmt.Errorf("password is required for sudo")
							}
							if len(s) < 8 {
								return fmt.Errorf("password must be at least 8 characters")
							}
							return nil
						})
				},
				value: func() string { return "••••••••" },
			},
		)
	}

	if contains(selectedFeatures, "ssh") {
		steps = append(steps,
			wizardStep{
				section: "SSH Hardening",
				label:   "Disable root login",
				fieldFn: func() huh.Field {
					cfg := system.SSHConfig{DisableRootLogin: sshCfg.DisableRootLogin, DisablePasswordAuth: sshCfg.DisablePasswordAuth, Port: sshPort, AuthorizedKeyUser: userName}
					cmds := (&modules.SSHModule{}).Plan(&cfg)
					return huh.NewConfirm().
						Title("Disable root login via SSH?").
						Description(
							"The root account has full system access and is the most targeted\n"+
								"by automated attacks. Disabling it forces use of a regular user\n"+
								"with sudo, adding an extra layer of protection.\n\n"+
								"Default: Yes (strongly recommended)"+
								formatPlan(cmds)).
						Value(&sshCfg.DisableRootLogin)
				},
				value: func() string { return ternaryStr(sshCfg.DisableRootLogin, "yes", "no") },
			},
			wizardStep{
				section: "SSH Hardening",
				label:   "Disable password auth",
				fieldFn: func() huh.Field {
					cfg := system.SSHConfig{DisableRootLogin: sshCfg.DisableRootLogin, DisablePasswordAuth: sshCfg.DisablePasswordAuth, Port: sshPort, AuthorizedKeyUser: userName}
					cmds := (&modules.SSHModule{}).Plan(&cfg)
					return huh.NewConfirm().
						Title("Disable password authentication?").
						Description(
							"Password-based SSH is vulnerable to brute-force attacks. SSH keys\n"+
								"use cryptographic authentication that is virtually impossible to\n"+
								"guess. Ensure you have an SSH key set up before enabling.\n\n"+
								"Default: Yes (requires SSH key to be already configured)"+
								formatPlan(cmds)).
						Value(&sshCfg.DisablePasswordAuth)
				},
				value: func() string { return ternaryStr(sshCfg.DisablePasswordAuth, "yes", "no") },
			},
			wizardStep{
				section: "SSH Hardening",
				label:   "SSH port",
				fieldFn: func() huh.Field {
					cfg := system.SSHConfig{DisableRootLogin: sshCfg.DisableRootLogin, DisablePasswordAuth: sshCfg.DisablePasswordAuth, Port: sshPort, AuthorizedKeyUser: userName}
					cmds := (&modules.SSHModule{}).Plan(&cfg)
					return huh.NewInput().
						Title("SSH port").
						Description(
							"Moving SSH off port 22 dramatically reduces automated scan noise.\n"+
								"Bots overwhelmingly target port 22. This won't stop determined\n"+
								"attackers but cuts log spam significantly.\n\n"+
								"Default: 2222"+
								formatPlan(cmds)).
						Value(&sshPort).
						Validate(func(s string) error {
							port, err := strconv.Atoi(s)
							if err != nil || port < 1 || port > 65535 {
								return fmt.Errorf("enter a valid port (1-65535)")
							}
							return nil
						})
				},
				value: func() string { return sshPort },
			},
		)
		if !contains(selectedFeatures, "user") {
			steps = append(steps,
				wizardStep{
					section: "SSH Hardening",
					label:   "Add SSH public key",
					fieldFn: func() huh.Field {
						cfg := system.SSHConfig{DisableRootLogin: sshCfg.DisableRootLogin, DisablePasswordAuth: sshCfg.DisablePasswordAuth, Port: sshPort, AuthorizedKey: sshKey}
						cmds := (&modules.SSHModule{}).Plan(&cfg)
						return huh.NewConfirm().
							Title("Add an authorized SSH public key to root?").
							Description(
								"Adds your public key to /root/.ssh/authorized_keys. Use this only\n"+
									"if you did not create a new user. Recommended: create a user instead.\n\n"+
									"Default: Yes"+
									formatPlan(cmds)).
							Value(&addSSHKey)
					},
					value: func() string { return ternaryStr(addSSHKey, "yes", "no") },
				},
			)
		}
	}

	if contains(selectedFeatures, "ufw") {
		steps = append(steps,
			wizardStep{
				section: "UFW Firewall",
				label:   "Allowed ports",
				fieldFn: func() huh.Field {
					parsed := make([]string, 0)
					for _, p := range strings.Split(portsStr, ",") {
						if t := strings.TrimSpace(p); t != "" {
							parsed = append(parsed, t)
						}
					}
					cfg := system.UFWConfig{AllowedPorts: parsed, RateLimitSSH: ufwCfg.RateLimitSSH}
					cmds := (&modules.UFWModule{}).Plan(&cfg)
					return huh.NewInput().
						Title("Allowed incoming ports").
						Description(
							"UFW will block all incoming traffic by default and only allow\n"+
								"the ports listed here. You need at least your SSH port to\n"+
								"stay connected. Add 80/tcp and 443/tcp for a web server.\n\n"+
								"Format: comma-separated, e.g. 2222/tcp, 80/tcp, 443/tcp"+
								formatPlan(cmds)).
						Value(&portsStr).
						Validate(func(s string) error {
							if strings.TrimSpace(s) == "" {
								return fmt.Errorf("at least one port is required")
							}
							return nil
						})
				},
				value: func() string { return portsStr },
			},
			wizardStep{
				section: "UFW Firewall",
				label:   "Rate-limit SSH",
				fieldFn: func() huh.Field {
					parsed := make([]string, 0)
					for _, p := range strings.Split(portsStr, ",") {
						if t := strings.TrimSpace(p); t != "" {
							parsed = append(parsed, t)
						}
					}
					cfg := system.UFWConfig{AllowedPorts: parsed, RateLimitSSH: ufwCfg.RateLimitSSH}
					cmds := (&modules.UFWModule{}).Plan(&cfg)
					return huh.NewConfirm().
						Title("Rate-limit SSH port?").
						Description(
							"UFW rate limiting allows max 6 connections per 30 seconds from\n"+
								"a single IP. This slows down brute-force attacks without\n"+
								"affecting normal interactive SSH usage.\n\n"+
								"Default: Yes"+
								formatPlan(cmds)).
						Value(&ufwCfg.RateLimitSSH)
				},
				value: func() string { return ternaryStr(ufwCfg.RateLimitSSH, "yes", "no") },
			},
		)
	}

	if contains(selectedFeatures, "fail2ban") {
		steps = append(steps,
			wizardStep{
				section: "fail2ban",
				label:   "Max retries",
				fieldFn: func() huh.Field {
					maxRetry, _ := strconv.Atoi(maxRetryStr)
					banTime, _ := strconv.Atoi(banTimeStr)
					if maxRetry == 0 {
						maxRetry = 3
					}
					if banTime == 0 {
						banTime = 86400
					}
					cfg := system.Fail2BanConfig{MaxRetry: maxRetry, BanTime: banTime}
					cmds := (&modules.Fail2BanModule{}).Plan(&cfg)
					return huh.NewInput().
						Title("Max retries before ban").
						Description(
							"After this many failed SSH login attempts from one IP, fail2ban\n"+
								"bans it. Lower values are more aggressive but could lock out\n"+
								"legitimate users who mistype their password.\n\n"+
								"Default: 3 (good balance between security and usability)"+
								formatPlan(cmds)).
						Value(&maxRetryStr).
						Validate(func(s string) error {
							n, err := strconv.Atoi(s)
							if err != nil || n < 1 {
								return fmt.Errorf("enter a positive number")
							}
							return nil
						})
				},
				value: func() string { return maxRetryStr },
			},
			wizardStep{
				section: "fail2ban",
				label:   "Ban time",
				fieldFn: func() huh.Field {
					maxRetry, _ := strconv.Atoi(maxRetryStr)
					banTime, _ := strconv.Atoi(banTimeStr)
					if maxRetry == 0 {
						maxRetry = 3
					}
					if banTime == 0 {
						banTime = 86400
					}
					cfg := system.Fail2BanConfig{MaxRetry: maxRetry, BanTime: banTime}
					cmds := (&modules.Fail2BanModule{}).Plan(&cfg)
					return huh.NewInput().
						Title("Ban time (seconds)").
						Description(
							"How long a banned IP stays blocked. Longer bans punish attackers\n"+
								"more, but also affect anyone accidentally banned. The IP is\n"+
								"automatically unbanned after this duration.\n\n"+
								"Default: 86400 (24 hours)  —  3600 = 1h, 604800 = 1w"+
								formatPlan(cmds)).
						Value(&banTimeStr).
						Validate(func(s string) error {
							n, err := strconv.Atoi(s)
							if err != nil || n < 60 {
								return fmt.Errorf("enter at least 60 seconds")
							}
							return nil
						})
				},
				value: func() string { return banTimeStr + "s" },
			},
		)
	}

	if contains(selectedFeatures, "sysctl") {
		steps = append(steps,
			wizardStep{
				section: "Kernel Hardening",
				label:   "Enable",
				fieldFn: func() huh.Field {
					cmds := (&modules.SysctlModule{}).Plan(&sysctlCfg)
					return huh.NewNote().
						Title("Kernel Hardening").
						Description(
							"Apply sysctl security settings: reverse path filtering,\n"+
								"SYN cookies, disable source routing, ASLR."+
								formatPlan(cmds)).
						Next(true).
						NextLabel("Next")
				},
				value: func() string { return "enabled" },
			},
		)
	}

	if contains(selectedFeatures, "apparmor") {
		steps = append(steps,
			wizardStep{
				section: "AppArmor",
				label:   "Enable",
				fieldFn: func() huh.Field {
					cmds := (&modules.AppArmorModule{}).Plan(&apparmorCfg)
					return huh.NewNote().
						Title("AppArmor").
						Description(
							"Ensure AppArmor is enabled and in enforcing mode.\n"+
								"AppArmor provides mandatory access control for applications."+
								formatPlan(cmds)).
						Next(true).
						NextLabel("Next")
				},
				value: func() string { return "enabled" },
			},
		)
	}

	if contains(selectedFeatures, "shm") {
		steps = append(steps,
			wizardStep{
				section: "/dev/shm Hardening",
				label:   "Enable",
				fieldFn: func() huh.Field {
					cmds := (&modules.ShmModule{}).Plan(&shmCfg)
					return huh.NewNote().
						Title("/dev/shm Hardening").
						Description(
							"Mount shared memory with noexec,nosuid,nodev to reduce\n"+
								"risk of executable abuse in /dev/shm."+
								formatPlan(cmds)).
						Next(true).
						NextLabel("Next")
				},
				value: func() string { return "enabled" },
			},
		)
	}

	if contains(selectedFeatures, "auditd") {
		steps = append(steps,
			wizardStep{
				section: "auditd",
				label:   "Enable",
				fieldFn: func() huh.Field {
					cmds := (&modules.AuditdModule{}).Plan(&auditdCfg)
					return huh.NewNote().
						Title("auditd").
						Description(
							"Enable audit logging for auth and sudo events.\n"+
								"Useful for forensics and compliance."+
								formatPlan(cmds)).
						Next(true).
						NextLabel("Next")
				},
				value: func() string { return "enabled" },
			},
		)
	}

	if contains(selectedFeatures, "timesync") {
		steps = append(steps,
			wizardStep{
				section: "Time Sync",
				label:   "Enable",
				fieldFn: func() huh.Field {
					cmds := (&modules.TimesyncModule{}).Plan(&timesyncCfg)
					return huh.NewNote().
						Title("Time Sync").
						Description(
							"Ensure system time is synchronized via systemd-timesyncd,\n"+
								"chrony, or ntp. Important for logs and TLS."+
								formatPlan(cmds)).
						Next(true).
						NextLabel("Next")
				},
				value: func() string { return "enabled" },
			},
		)
	}

	if contains(selectedFeatures, "upgrades") {
		steps = append(steps,
			wizardStep{
				section: "Unattended Upgrades",
				label:   "Enable",
				fieldFn: func() huh.Field {
					cmds := (&modules.UpgradesModule{}).Plan(&upgCfg)
					return huh.NewNote().
						Title("Unattended Upgrades").
						Description(
							"Automatic security updates will be enabled.\n\n"+
								"The system will install security patches automatically.\n"+
								"Reboots are not automatic — you can reboot manually when needed."+
								formatPlan(cmds)).
						Next(true).
						NextLabel("Next")
				},
				value: func() string { return "enabled" },
			},
		)
	}

	total := len(steps)
	if contains(selectedFeatures, "ssh") && !contains(selectedFeatures, "user") {
		total++
	}
	if contains(selectedFeatures, "user") {
		total += 2
	}
	var answered []answeredStep

	stepNum := 0
	for _, s := range steps {
		stepNum++
		renderHeader(stepNum, total, answered)
		field := s.field
		if s.fieldFn != nil {
			field = s.fieldFn()
		}
		if err := runForm(field); err != nil {
			return err
		}
		answered = append(answered, answeredStep{section: s.section, label: s.label, val: s.value()})

		if s.label == "Password for sudo" {
			otherUsers, _ = modules.ListOtherUsers(strings.TrimSpace(userName))
			if len(otherUsers) > 0 {
				stepNum++
				renderHeader(stepNum, total, answered)
				var confirmRemove bool
				userList := strings.Join(otherUsers, ", ")
				userdelCmds := make([]string, len(otherUsers))
				for i, u := range otherUsers {
					userdelCmds[i] = "userdel -r " + u
				}
				if err := huh.NewForm(huh.NewGroup(
					huh.NewNote().
						Title("Other users found").
						Description(
							"The following users exist on this system: " + userList + "\n\n"+
								"Removing unused users reduces attack surface. This will delete\n"+
								"the users and their home directories. Ensure no one is logged in\n"+
								"as these users before proceeding."+
								formatPlan(userdelCmds)),
					huh.NewConfirm().
						Title("Remove these users?").
						Value(&confirmRemove).
						Affirmative("Yes, remove them").
						Negative("No, keep them"),
				)).WithTheme(wizardTheme()).Run(); err != nil {
					return err
				}
				removeOtherUsers = confirmRemove
				answered = append(answered, answeredStep{
					section: "Create User",
					label:   "Remove other users",
					val:     ternaryStr(removeOtherUsers, "yes", "no"),
				})
			}
		}

		if s.label == "Add SSH public key" && addSSHKey {
			stepNum++
			renderHeader(stepNum, total, answered)
			if err := huh.NewForm(huh.NewGroup(
				huh.NewText().
					Title("Paste your SSH public key").
					Description(
						"Paste the contents of your public key file (e.g. ~/.ssh/id_ed25519.pub).\n"+
							"It starts with 'ssh-ed25519', 'ssh-rsa', or similar.\n\n"+
							"This will be appended to /root/.ssh/authorized_keys.").
					Value(&sshKey).
					Validate(func(s string) error {
						s = strings.TrimSpace(s)
						if s == "" {
							return fmt.Errorf("key cannot be empty")
						}
						if !strings.HasPrefix(s, "ssh-") && !strings.HasPrefix(s, "ecdsa-") {
							return fmt.Errorf("doesn't look like a public key (should start with ssh- or ecdsa-)")
						}
						return nil
					}),
			)).WithTheme(wizardTheme()).Run(); err != nil {
				return err
			}
			answered = append(answered, answeredStep{
				section: "SSH Hardening",
				label:   "SSH public key",
				val:     sshKey[:min(30, len(sshKey))] + "…",
			})
		}
	}

	sshCfg.Port = sshPort

	if contains(selectedFeatures, "user") {
		userCfg.Username = strings.TrimSpace(userName)
		userCfg.AuthorizedKey = strings.TrimSpace(sshKey)
		userCfg.Password = userPassword
		sshCfg.AuthorizedKeyUser = userCfg.Username
	} else {
		sshCfg.AuthorizedKey = strings.TrimSpace(sshKey)
	}

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
	if contains(selectedFeatures, "ssh") {
		f2bCfg.SSHPort = sshCfg.Port
		ufwCfg.SSHPort = sshCfg.Port
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

	renderHeader(0, 0, answered)

	var confirm bool
	err = huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("Review your configuration").
				Description(buildSummary(selectedFeatures, &userCfg, &sshCfg, &ufwCfg, &f2bCfg, &upgCfg, &sysctlCfg, &apparmorCfg, &shmCfg, &auditdCfg, &timesyncCfg, otherUsers, removeOtherUsers)),
			huh.NewConfirm().
				Title("Apply these changes?").
				Value(&confirm).
				Affirmative("Yes, harden this server").
				Negative("Cancel"),
		),
	).WithTheme(wizardTheme()).Run()
	if err != nil {
		return err
	}

	if !confirm {
		fmt.Println("\n  Cancelled. No changes were made.")
		return nil
	}

	type applyResult struct {
		name string
		err  error
	}

	var results []applyResult

	if DryRun {
		fmt.Println()
		fmt.Println("  Dry run — no changes applied.")
		for _, f := range selectedFeatures {
			fmt.Printf("  %s %s (skipped)\n", checkStyle.Render("✓"), f)
		}
	} else {
		applyFn := func() {
			results = append(results, applyResult{"Update package lists", system.AptUpdate()})

			if contains(selectedFeatures, "user") && userCfg.Username != "" {
				if removeOtherUsers && len(otherUsers) > 0 {
					err := modules.RemoveOtherUsers(otherUsers)
					results = append(results, applyResult{"Remove other users", err})
				}
				m := &modules.UserModule{}
				results = append(results, applyResult{m.Name(), m.Apply(&userCfg)})
			}
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
			if contains(selectedFeatures, "sysctl") {
				m := &modules.SysctlModule{}
				results = append(results, applyResult{m.Name(), m.Apply(&sysctlCfg)})
			}
			if contains(selectedFeatures, "apparmor") {
				m := &modules.AppArmorModule{}
				results = append(results, applyResult{m.Name(), m.Apply(&apparmorCfg)})
			}
			if contains(selectedFeatures, "shm") {
				m := &modules.ShmModule{}
				results = append(results, applyResult{m.Name(), m.Apply(&shmCfg)})
			}
			if contains(selectedFeatures, "auditd") {
				m := &modules.AuditdModule{}
				results = append(results, applyResult{m.Name(), m.Apply(&auditdCfg)})
			}
			if contains(selectedFeatures, "timesync") {
				m := &modules.TimesyncModule{}
				results = append(results, applyResult{m.Name(), m.Apply(&timesyncCfg)})
			}
			if contains(selectedFeatures, "upgrades") {
				m := &modules.UpgradesModule{}
				results = append(results, applyResult{m.Name(), m.Apply(&upgCfg)})
				results = append(results, applyResult{"Upgrade packages", system.AptUpgrade()})
			}
		}

		_ = spinner.New().
			Title("Applying hardening configuration...").
			Action(applyFn).
			Run()

		savedCfg := &system.SavedConfig{}
		if contains(selectedFeatures, "user") && userCfg.Username != "" {
			savedCfg.User = &userCfg
		}
		if contains(selectedFeatures, "ssh") {
			savedCfg.SSH = &sshCfg
		}
		if contains(selectedFeatures, "ufw") {
			savedCfg.UFW = &ufwCfg
		}
		if contains(selectedFeatures, "fail2ban") {
			savedCfg.Fail2Ban = &f2bCfg
		}
		if contains(selectedFeatures, "sysctl") {
			savedCfg.Sysctl = &sysctlCfg
		}
		if contains(selectedFeatures, "apparmor") {
			savedCfg.AppArmor = &apparmorCfg
		}
		if contains(selectedFeatures, "shm") {
			savedCfg.Shm = &shmCfg
		}
		if contains(selectedFeatures, "auditd") {
			savedCfg.Auditd = &auditdCfg
		}
		if contains(selectedFeatures, "timesync") {
			savedCfg.Timesync = &timesyncCfg
		}
		if contains(selectedFeatures, "upgrades") {
			savedCfg.Upgrades = &upgCfg
		}

		if err := system.SaveConfig(savedCfg); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not save config to %s: %v\n", system.ConfigPath, err)
		}
	}

	fmt.Println()
	allPassed := true
	for _, r := range results {
		if r.err != nil {
			fmt.Printf("  ✗ %s: %v\n", r.name, r.err)
			allPassed = false
		} else {
			fmt.Printf("  %s %s\n", checkStyle.Render("✓"), r.name)
		}
	}

	fmt.Println()
	if allPassed {
		fmt.Println("  Server hardening complete.")
	} else {
		fmt.Println("  Some modules failed. Review the errors above.")
	}

	if contains(selectedFeatures, "ssh") {
		fmt.Println()
		fmt.Println(warnStyle.Render("  ⚠  Test SSH access in a new terminal before closing this session!"))
		loginUser := "root"
		if contains(selectedFeatures, "user") && userCfg.Username != "" {
			loginUser = userCfg.Username
		}
		if sshCfg.Port != "22" {
			fmt.Printf(dimStyle.Render("     ssh -p %s %s@host\n"), sshCfg.Port, loginUser)
		} else {
			fmt.Printf(dimStyle.Render("     ssh %s@host\n"), loginUser)
		}
	}

	fmt.Println()
	fmt.Println(dimStyle.Render("  Run 'safeup verify' to check your configuration."))
	fmt.Println(dimStyle.Render("  Run 'safeup audit' to scan for security concerns."))
	fmt.Println()

	return nil
}

func buildSummary(features []string, user *system.UserConfig, ssh *system.SSHConfig, ufw *system.UFWConfig, f2b *system.Fail2BanConfig, upg *system.UpgradesConfig, _ *system.SysctlConfig, _ *system.AppArmorConfig, _ *system.ShmConfig, _ *system.AuditdConfig, _ *system.TimesyncConfig, otherUsers []string, removeOtherUsers bool) string {
	var lines []string

	if contains(features, "user") && user.Username != "" {
		lines = append(lines, "Create User")
		lines = append(lines, fmt.Sprintf("  Username:         %s", user.Username))
		lines = append(lines, fmt.Sprintf("  SSH key:          %s", ternaryStr(user.AuthorizedKey != "", "yes", "no")))
		lines = append(lines, fmt.Sprintf("  Sudo:             password required"))
		lines = append(lines, fmt.Sprintf("  Password:         %s", ternaryStr(user.Password != "", "set", "set later with passwd")))
		if len(otherUsers) > 0 {
			lines = append(lines, fmt.Sprintf("  Remove other users (%s): %s", strings.Join(otherUsers, ", "), ternaryStr(removeOtherUsers, "yes", "no")))
		}
		lines = append(lines, "")
	}

	if contains(features, "ssh") {
		lines = append(lines, "SSH Hardening")
		lines = append(lines, fmt.Sprintf("  Root login:     %s", ternaryStr(ssh.DisableRootLogin, "disabled", "allowed")))
		lines = append(lines, fmt.Sprintf("  Password auth:  %s", ternaryStr(ssh.DisablePasswordAuth, "disabled", "allowed")))
		lines = append(lines, fmt.Sprintf("  Port:           %s", ssh.Port))
		if !contains(features, "user") {
			lines = append(lines, fmt.Sprintf("  SSH key (root): %s", ternaryStr(ssh.AuthorizedKey != "", "yes", "no")))
		}
		lines = append(lines, "")
	}

	if contains(features, "ufw") {
		lines = append(lines, "UFW Firewall")
		lines = append(lines, "  Default:        deny incoming, allow outgoing")
		lines = append(lines, fmt.Sprintf("  Allowed ports:  %s", strings.Join(ufw.AllowedPorts, ", ")))
		lines = append(lines, fmt.Sprintf("  Rate-limit SSH: %s", ternaryStr(ufw.RateLimitSSH, "yes", "no")))
		lines = append(lines, "")
	}

	if contains(features, "fail2ban") {
		lines = append(lines, "fail2ban")
		lines = append(lines, fmt.Sprintf("  Max retries:    %d", f2b.MaxRetry))
		lines = append(lines, fmt.Sprintf("  Ban time:       %ds", f2b.BanTime))
		lines = append(lines, "")
	}

	if contains(features, "sysctl") {
		lines = append(lines, "Kernel Hardening")
		lines = append(lines, "  sysctl security settings: enabled")
		lines = append(lines, "")
	}

	if contains(features, "apparmor") {
		lines = append(lines, "AppArmor")
		lines = append(lines, "  Enforce mode: enabled")
		lines = append(lines, "")
	}

	if contains(features, "shm") {
		lines = append(lines, "/dev/shm Hardening")
		lines = append(lines, "  noexec,nosuid,nodev: enabled")
		lines = append(lines, "")
	}

	if contains(features, "auditd") {
		lines = append(lines, "auditd")
		lines = append(lines, "  Auth and sudo audit: enabled")
		lines = append(lines, "")
	}

	if contains(features, "timesync") {
		lines = append(lines, "Time Sync")
		lines = append(lines, "  NTP/time sync: enabled")
		lines = append(lines, "")
	}

	if contains(features, "upgrades") {
		lines = append(lines, "Unattended Upgrades")
		lines = append(lines, "  Automatic security updates: enabled")
	}

	return strings.Join(lines, "\n")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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
