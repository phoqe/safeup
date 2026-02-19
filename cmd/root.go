package cmd

import (
	"github.com/spf13/cobra"
)

var (
	Version = "dev"
	DryRun  bool
)

var rootCmd = &cobra.Command{
	Use:     "safeup",
	Short:   "Interactive VPS hardening for Ubuntu",
	Long:    "SafeUp hardens your Ubuntu server interactively — SSH, UFW, fail2ban, and unattended upgrades.",
	Version: Version,
}

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.PersistentFlags().BoolVar(&DryRun, "dry-run", false, "skip OS/root checks and don't apply changes (for testing)")
}

func Execute() error {
	return rootCmd.Execute()
}
