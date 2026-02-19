package modules

import (
	"github.com/phoqe/safeup/internal/system"
)

type TimesyncModule struct{}

func (m *TimesyncModule) Name() string        { return "Time Sync" }
func (m *TimesyncModule) Description() string { return "Ensure system time is synchronized" }

func (m *TimesyncModule) Apply(cfg *system.TimesyncConfig) error {
	tryService := func(name string) error {
		_ = system.ServiceAction(name, "enable")
		return system.ServiceAction(name, "start")
	}

	if system.IsInstalled("chrony") {
		return tryService("chrony")
	}
	if system.IsInstalled("ntp") {
		return tryService("ntp")
	}
	if system.IsInstalled("systemd-timesyncd") {
		return tryService("systemd-timesyncd")
	}

	if err := system.AptInstall("systemd-timesyncd"); err != nil {
		return err
	}
	return tryService("systemd-timesyncd")
}

func (m *TimesyncModule) Verify(cfg *system.TimesyncConfig) *VerifyResult {
	result := &VerifyResult{ModuleName: m.Name()}

	active := system.IsServiceActive("systemd-timesyncd") ||
		system.IsServiceActive("chrony") ||
		system.IsServiceActive("ntp")

	result.Checks = append(result.Checks, Check{
		Name:     "time sync active",
		Status:   boolCheck(active),
		Expected: "active",
		Actual:   ternary(active, "active", "inactive"),
	})

	return result
}
