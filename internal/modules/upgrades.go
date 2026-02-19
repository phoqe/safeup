package modules

import (
	"fmt"
	"os"
	"strings"

	"github.com/phoqe/safeup/internal/system"
)

const (
	unattendedConfigPath = "/etc/apt/apt.conf.d/50unattended-upgrades"
	autoUpgradesPath     = "/etc/apt/apt.conf.d/20auto-upgrades"
)

type UpgradesModule struct{}

func (m *UpgradesModule) Name() string        { return "Unattended Upgrades" }
func (m *UpgradesModule) Description() string { return "Automatic security updates" }

func (m *UpgradesModule) Apply(cfg *system.UpgradesConfig) error {
	if !system.IsInstalled("unattended-upgrades") {
		if err := system.AptInstall("unattended-upgrades"); err != nil {
			return fmt.Errorf("failed to install unattended-upgrades: %w", err)
		}
	}

	if _, err := system.BackupFile(unattendedConfigPath); err != nil {
		return fmt.Errorf("backup failed: %w", err)
	}

	data, err := os.ReadFile(unattendedConfigPath)
	if err != nil {
		return fmt.Errorf("cannot read unattended-upgrades config: %w", err)
	}

	content := string(data)

	if cfg.AutoReboot {
		content = setAptOption(content, "Unattended-Upgrade::Automatic-Reboot", "true")
		content = setAptOption(content, "Unattended-Upgrade::Automatic-Reboot-Time", fmt.Sprintf("%q", cfg.RebootTime))
	} else {
		content = setAptOption(content, "Unattended-Upgrade::Automatic-Reboot", "false")
	}

	if err := os.WriteFile(unattendedConfigPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("cannot write unattended-upgrades config: %w", err)
	}

	autoUpgradesContent := `APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
`
	if err := os.WriteFile(autoUpgradesPath, []byte(autoUpgradesContent), 0644); err != nil {
		return fmt.Errorf("cannot write auto-upgrades config: %w", err)
	}

	return nil
}

func (m *UpgradesModule) Verify(cfg *system.UpgradesConfig) *VerifyResult {
	result := &VerifyResult{ModuleName: m.Name()}

	autoData, err := os.ReadFile(autoUpgradesPath)
	if err != nil {
		result.Checks = append(result.Checks, Check{
			Name:   "auto-upgrades config",
			Status: StatusFail,
			Actual: "config not found",
		})
		return result
	}

	autoContent := string(autoData)
	enabled := strings.Contains(autoContent, `Unattended-Upgrade "1"`)
	result.Checks = append(result.Checks, Check{
		Name:     "enabled",
		Status:   boolCheck(enabled),
		Expected: "enabled",
		Actual:   ternary(enabled, "enabled", "disabled"),
	})

	data, err := os.ReadFile(unattendedConfigPath)
	if err != nil {
		return result
	}

	content := string(data)

	if cfg.AutoReboot {
		hasReboot := strings.Contains(content, `Automatic-Reboot "true"`)
		result.Checks = append(result.Checks, Check{
			Name:     "auto-reboot",
			Status:   boolCheck(hasReboot),
			Expected: "true",
			Actual:   ternary(hasReboot, "true", "false"),
		})
	}

	return result
}

func setAptOption(content, key, value string) string {
	searchKey := key + " "
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		if strings.Contains(trimmed, key) {
			newLine := fmt.Sprintf("%s %s;", key, value)
			return strings.Replace(content, line, newLine, 1)
		}
	}

	_ = searchKey
	return content + fmt.Sprintf("\n%s %s;\n", key, value)
}
