package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/phoqe/safeup/internal/modules"
	"github.com/phoqe/safeup/internal/system"
)

var applyConfigPath string

var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply configuration from file (non-interactive)",
	RunE:  runApply,
}

func init() {
	rootCmd.AddCommand(applyCmd)
	applyCmd.Flags().StringVarP(&applyConfigPath, "config", "c", "", "path to config file (JSON or YAML)")
}

func runApply(cmd *cobra.Command, args []string) error {
	if applyConfigPath == "" {
		return fmt.Errorf("--config is required")
	}

	if !DryRun {
		if err := system.RequireRoot(); err != nil {
			return err
		}
		if _, err := system.DetectOS(); err != nil {
			return err
		}
	}

	data, err := os.ReadFile(applyConfigPath)
	if err != nil {
		return fmt.Errorf("cannot read config: %w", err)
	}

	var cfg system.SavedConfig
	if strings.HasSuffix(strings.ToLower(applyConfigPath), ".yaml") || strings.HasSuffix(strings.ToLower(applyConfigPath), ".yml") {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("invalid config: %w", err)
		}
	} else {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("invalid config: %w", err)
		}
	}

	if DryRun {
		fmt.Println("Dry run — would apply config from", applyConfigPath)
		return nil
	}

	type result struct {
		name string
		err  error
	}
	var results []result

	if cfg.User != nil && cfg.User.Username != "" {
		m := &modules.UserModule{}
		results = append(results, result{m.Name(), m.Apply(cfg.User)})
	}
	if cfg.SSH != nil {
		m := &modules.SSHModule{}
		results = append(results, result{m.Name(), m.Apply(cfg.SSH)})
	}
	if cfg.UFW != nil {
		m := &modules.UFWModule{}
		results = append(results, result{m.Name(), m.Apply(cfg.UFW)})
	}
	if cfg.Fail2Ban != nil {
		m := &modules.Fail2BanModule{}
		results = append(results, result{m.Name(), m.Apply(cfg.Fail2Ban)})
	}
	if cfg.Sysctl != nil {
		m := &modules.SysctlModule{}
		results = append(results, result{m.Name(), m.Apply(cfg.Sysctl)})
	}
	if cfg.AppArmor != nil {
		m := &modules.AppArmorModule{}
		results = append(results, result{m.Name(), m.Apply(cfg.AppArmor)})
	}
	if cfg.Shm != nil {
		m := &modules.ShmModule{}
		results = append(results, result{m.Name(), m.Apply(cfg.Shm)})
	}
	if cfg.Auditd != nil {
		m := &modules.AuditdModule{}
		results = append(results, result{m.Name(), m.Apply(cfg.Auditd)})
	}
	if cfg.Timesync != nil {
		m := &modules.TimesyncModule{}
		results = append(results, result{m.Name(), m.Apply(cfg.Timesync)})
	}
	if cfg.Upgrades != nil {
		m := &modules.UpgradesModule{}
		results = append(results, result{m.Name(), m.Apply(cfg.Upgrades)})
	}

	allPassed := true
	for _, r := range results {
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "✗ %s: %v\n", r.name, r.err)
			allPassed = false
		} else {
			fmt.Printf("✓ %s\n", r.name)
		}
	}

	if err := system.SaveConfig(&cfg); err != nil {
		return fmt.Errorf("cannot save config: %w", err)
	}

	if !allPassed {
		os.Exit(1)
	}

	return nil
}
