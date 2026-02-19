package modules

import (
	"fmt"
	"os"
	"strings"

	"github.com/phoqe/safeup/internal/system"
)

const sysctlPath = "/etc/sysctl.d/99-safeup.conf"

var sysctlSettings = []struct{ key, value string }{
	{"net.ipv4.conf.all.rp_filter", "1"},
	{"net.ipv4.tcp_syncookies", "1"},
	{"net.ipv4.conf.all.accept_source_route", "0"},
	{"net.ipv4.conf.default.accept_source_route", "0"},
	{"net.ipv4.icmp_echo_ignore_broadcasts", "1"},
	{"kernel.randomize_va_space", "2"},
}

type SysctlModule struct{}

func (m *SysctlModule) Name() string        { return "Kernel Hardening" }
func (m *SysctlModule) Description() string { return "Apply sysctl security settings" }

func (m *SysctlModule) Apply(cfg *system.SysctlConfig) error {
	var lines []string
	for _, s := range sysctlSettings {
		lines = append(lines, fmt.Sprintf("%s = %s", s.key, s.value))
	}

	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(sysctlPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("cannot write sysctl config: %w", err)
	}

	result, err := system.Run("sysctl", "--system")
	if err != nil {
		return fmt.Errorf("sysctl apply failed: %w", err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("sysctl apply failed: %s", result.Stderr)
	}

	return nil
}

func (m *SysctlModule) Plan(cfg *system.SysctlConfig) []string {
	var cmds []string
	cmds = append(cmds, "write /etc/sysctl.d/99-safeup.conf")
	cmds = append(cmds, "sysctl --system")
	return cmds
}

func (m *SysctlModule) Verify(cfg *system.SysctlConfig) *VerifyResult {
	result := &VerifyResult{ModuleName: m.Name()}

	if _, err := os.Stat(sysctlPath); err != nil {
		result.Checks = append(result.Checks, Check{
			Name:   "config exists",
			Status: StatusFail,
			Actual: "config not found",
		})
		return result
	}

	for _, s := range sysctlSettings {
		actual := getSysctlValue(s.key)
		ok := actual == s.value
		result.Checks = append(result.Checks, Check{
			Name:     s.key,
			Status:   boolCheck(ok),
			Expected: s.value,
			Actual:   actual,
		})
	}

	return result
}

func getSysctlValue(key string) string {
	result, err := system.Run("sysctl", "-n", key)
	if err != nil || result.ExitCode != 0 {
		return ""
	}
	return strings.TrimSpace(result.Stdout)
}
