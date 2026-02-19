package cmd

import (
	"github.com/spf13/cobra"
)

var Version = "dev"

var rootCmd = &cobra.Command{
	Use:     "safeup",
	Short:   "Interactive VPS hardening for Ubuntu",
	Long:    "SafeUp hardens your Ubuntu server interactively — SSH, UFW, fail2ban, and unattended upgrades.",
	Version: Version,
}

func Execute() error {
	return rootCmd.Execute()
}
