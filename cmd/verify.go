package cmd

import (
	"fmt"
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/phoqe/safeup/internal/modules"
	"github.com/phoqe/safeup/internal/system"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Audit server hardening against expected configuration",
	RunE:  runVerify,
}

func init() {
	rootCmd.AddCommand(verifyCmd)
}

func runVerify(cmd *cobra.Command, args []string) error {
	if err := system.RequireRoot(); err != nil {
		return err
	}

	osInfo, err := system.DetectOS()
	if err != nil {
		return err
	}

	cfg, err := system.LoadConfig()
	if err != nil {
		return fmt.Errorf("cannot load config from %s: %w", system.ConfigPath, err)
	}
	if cfg == nil {
		return fmt.Errorf("no configuration found at %s — run 'safeup init' first", system.ConfigPath)
	}

	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212"))
	subtitleStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	moduleStyle := lipgloss.NewStyle().Bold(true)
	passStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	failStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	warnStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("11"))

	fmt.Println()
	fmt.Println(titleStyle.Render("  SafeUp Verify"))
	fmt.Println(subtitleStyle.Render("  " + osInfo.PrettyName))
	fmt.Println()

	var results []*modules.VerifyResult

	if cfg.User != nil {
		m := &modules.UserModule{}
		results = append(results, m.Verify(cfg.User))
	}
	if cfg.SSH != nil {
		m := &modules.SSHModule{}
		results = append(results, m.Verify(cfg.SSH))
	}
	if cfg.UFW != nil {
		m := &modules.UFWModule{}
		results = append(results, m.Verify(cfg.UFW))
	}
	if cfg.Fail2Ban != nil {
		m := &modules.Fail2BanModule{}
		results = append(results, m.Verify(cfg.Fail2Ban))
	}
	if cfg.Upgrades != nil {
		m := &modules.UpgradesModule{}
		results = append(results, m.Verify(cfg.Upgrades))
	}

	totalChecks := 0
	passedChecks := 0

	for _, r := range results {
		fmt.Printf("  %s\n", moduleStyle.Render(r.ModuleName))
		for _, c := range r.Checks {
			totalChecks++
			var icon string
			var detail string
			switch c.Status {
			case modules.StatusPass:
				passedChecks++
				icon = passStyle.Render("✓")
				detail = c.Name
			case modules.StatusFail:
				icon = failStyle.Render("✗")
				if c.Expected != "" && c.Actual != "" {
					detail = fmt.Sprintf("%s (expected %s, got %s)", c.Name, c.Expected, c.Actual)
				} else if c.Actual != "" {
					detail = fmt.Sprintf("%s: %s", c.Name, c.Actual)
				} else {
					detail = c.Name
				}
			case modules.StatusWarn:
				icon = warnStyle.Render("⚠")
				if c.Expected != "" && c.Actual != "" {
					detail = fmt.Sprintf("%s (expected %s, got %s)", c.Name, c.Expected, c.Actual)
				} else {
					detail = c.Name
				}
			}
			fmt.Printf("    %s %s\n", icon, detail)
		}
		fmt.Println()
	}

	if totalChecks == passedChecks {
		fmt.Println(passStyle.Render(fmt.Sprintf("  All %d checks passed.", totalChecks)))
	} else {
		fmt.Println(subtitleStyle.Render(fmt.Sprintf("  %d/%d checks passed.", passedChecks, totalChecks)))
	}
	fmt.Println()

	if passedChecks < totalChecks {
		os.Exit(1)
	}

	return nil
}
