package modules

import (
	"fmt"
	"os"
	"strings"

	"github.com/phoqe/safeup/internal/system"
)

const autoUpgradesPath = "/etc/apt/apt.conf.d/20auto-upgrades"
const unattendedRebootPath = "/etc/apt/apt.conf.d/99-safeup-unattended-reboot"

type UpgradesModule struct{}

func (m *UpgradesModule) Name() string        { return "Unattended Upgrades" }
func (m *UpgradesModule) Description() string { return "Automatic security updates" }

func (m *UpgradesModule) Apply(cfg *system.UpgradesConfig) error {
	if !system.IsInstalled("unattended-upgrades") {
		if err := system.AptInstall("unattended-upgrades"); err != nil {
			return fmt.Errorf("failed to install unattended-upgrades: %w", err)
		}
	}

	autoUpgradesContent := `APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
`
	if err := os.WriteFile(autoUpgradesPath, []byte(autoUpgradesContent), 0644); err != nil {
		return fmt.Errorf("cannot write auto-upgrades config: %w", err)
	}

	rebootContent := `Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
`
	if err := os.WriteFile(unattendedRebootPath, []byte(rebootContent), 0644); err != nil {
		return fmt.Errorf("cannot write unattended-reboot config: %w", err)
	}

	return nil
}

func (m *UpgradesModule) Plan(cfg *system.UpgradesConfig) []string {
	var cmds []string
	cmds = append(cmds, "apt-get install -y unattended-upgrades")
	cmds = append(cmds, "write /etc/apt/apt.conf.d/20auto-upgrades")
	cmds = append(cmds, "write /etc/apt/apt.conf.d/99-safeup-unattended-reboot (Automatic-Reboot at 04:00)")
	return cmds
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

	rebootData, err := os.ReadFile(unattendedRebootPath)
	rebootConfigured := err == nil && strings.Contains(string(rebootData), "Automatic-Reboot")
	result.Checks = append(result.Checks, Check{
		Name:     "automatic reboot",
		Status:   boolCheck(rebootConfigured),
		Expected: "configured",
		Actual:   ternary(rebootConfigured, "configured", "not configured"),
	})

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
