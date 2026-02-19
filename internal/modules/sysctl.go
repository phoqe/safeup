package modules

import (
	"fmt"
	"os"
	"strings"

	"github.com/phoqe/safeup/internal/system"
)

const sysctlPath = "/etc/sysctl.d/zzz-safeup.conf"

type SysctlSetting struct{ Key, Value string }

var SysctlSettings = []SysctlSetting{
	{"net.ipv4.conf.all.rp_filter", "1"},
	{"net.ipv4.conf.default.rp_filter", "1"},
	{"net.ipv4.tcp_syncookies", "1"},
	{"net.ipv4.conf.all.accept_source_route", "0"},
	{"net.ipv4.conf.default.accept_source_route", "0"},
	{"net.ipv4.conf.all.accept_redirects", "0"},
	{"net.ipv4.conf.default.accept_redirects", "0"},
	{"net.ipv4.conf.all.send_redirects", "0"},
	{"net.ipv4.conf.default.send_redirects", "0"},
	{"net.ipv4.icmp_echo_ignore_broadcasts", "1"},
	{"net.ipv4.conf.all.log_martians", "1"},
	{"kernel.randomize_va_space", "2"},
	{"kernel.dmesg_restrict", "1"},
	{"kernel.kptr_restrict", "2"},
	{"kernel.sysrq", "0"},
	{"fs.suid_dumpable", "0"},
	{"fs.protected_hardlinks", "1"},
	{"fs.protected_symlinks", "1"},
	{"net.ipv6.conf.all.accept_redirects", "0"},
	{"net.ipv6.conf.default.accept_redirects", "0"},
}

func GetSysctlSettings() []SysctlSetting {
	return SysctlSettings
}

type SysctlModule struct{}

func (m *SysctlModule) Name() string        { return "Kernel Hardening" }
func (m *SysctlModule) Description() string { return "Apply sysctl security settings" }

func (m *SysctlModule) Apply(cfg *system.SysctlConfig) error {
	_ = os.Remove("/etc/sysctl.d/99-safeup.conf")

	var lines []string
	for _, s := range SysctlSettings {
		lines = append(lines, fmt.Sprintf("%s=%s", s.Key, s.Value))
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
	cmds = append(cmds, "write /etc/sysctl.d/zzz-safeup.conf")
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

	for _, s := range SysctlSettings {
		actual := getSysctlValue(s.Key)
		ok := actual == s.Value
		result.Checks = append(result.Checks, Check{
			Name:     s.Key,
			Status:   boolCheck(ok),
			Expected: s.Value,
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
