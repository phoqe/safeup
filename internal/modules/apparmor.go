package modules

import (
	"fmt"

	"github.com/phoqe/safeup/internal/system"
)

type AppArmorModule struct{}

func (m *AppArmorModule) Name() string        { return "AppArmor" }
func (m *AppArmorModule) Description() string { return "Ensure AppArmor is enabled and enforcing" }

func (m *AppArmorModule) Apply(cfg *system.AppArmorConfig) error {
	if !system.IsInstalled("apparmor") {
		if err := system.AptInstall("apparmor"); err != nil {
			return fmt.Errorf("failed to install apparmor: %w", err)
		}
	}

	result, err := system.Run("aa-status", "--enabled")
	if err != nil {
		return fmt.Errorf("apparmor status check failed: %w", err)
	}
	if result.ExitCode != 0 {
		startResult, err := system.Run("systemctl", "start", "apparmor")
		if err != nil {
			return fmt.Errorf("failed to start apparmor: %w", err)
		}
		if startResult.ExitCode != 0 {
			return fmt.Errorf("failed to start apparmor: %s", startResult.Stderr)
		}
	}

	return system.ServiceAction("apparmor", "enable")
}

func (m *AppArmorModule) Verify(cfg *system.AppArmorConfig) *VerifyResult {
	result := &VerifyResult{ModuleName: m.Name()}

	active := system.IsServiceActive("apparmor")
	result.Checks = append(result.Checks, Check{
		Name:     "service active",
		Status:   boolCheck(active),
		Expected: "active",
		Actual:   ternary(active, "active", "inactive"),
	})

	statusResult, err := system.Run("aa-status", "--enabled")
	enabled := err == nil && statusResult.ExitCode == 0
	result.Checks = append(result.Checks, Check{
		Name:     "enabled",
		Status:   boolCheck(enabled),
		Expected: "enabled",
		Actual:   ternary(enabled, "enabled", "disabled"),
	})

	return result
}
