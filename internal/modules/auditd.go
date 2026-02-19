package modules

import (
	"fmt"
	"os"
	"strings"

	"github.com/phoqe/safeup/internal/system"
)

const auditRulesPath = "/etc/audit/rules.d/safeup.rules"

var auditRules = []string{
	"-w /etc/passwd -p wa -k identity",
	"-w /etc/group -p wa -k identity",
	"-w /etc/shadow -p wa -k identity",
	"-w /etc/sudoers -p wa -k sudoers",
	"-w /etc/sudoers.d/ -p wa -k sudoers",
	"-w /usr/bin/sudo -p x -k sudo",
	"-w /usr/bin/sudoedit -p x -k sudo",
	"-w /usr/bin/su -p x -k su",
}

type AuditdModule struct{}

func (m *AuditdModule) Name() string        { return "auditd" }
func (m *AuditdModule) Description() string { return "Audit logging for auth and sudo events" }

func (m *AuditdModule) Apply(cfg *system.AuditdConfig) error {
	if !system.IsInstalled("auditd") {
		if err := system.AptInstall("auditd"); err != nil {
			return fmt.Errorf("failed to install auditd: %w", err)
		}
	}

	content := strings.Join(auditRules, "\n") + "\n"
	if err := os.WriteFile(auditRulesPath, []byte(content), 0640); err != nil {
		return fmt.Errorf("cannot write audit rules: %w", err)
	}

	if err := system.ServiceAction("auditd", "restart"); err != nil {
		return err
	}

	return system.ServiceAction("auditd", "enable")
}

func (m *AuditdModule) Verify(cfg *system.AuditdConfig) *VerifyResult {
	result := &VerifyResult{ModuleName: m.Name()}

	active := system.IsServiceActive("auditd")
	result.Checks = append(result.Checks, Check{
		Name:     "service active",
		Status:   boolCheck(active),
		Expected: "active",
		Actual:   ternary(active, "active", "inactive"),
	})

	if _, err := os.Stat(auditRulesPath); err != nil {
		result.Checks = append(result.Checks, Check{
			Name:   "rules file",
			Status: StatusFail,
			Actual: "not found",
		})
	} else {
		data, _ := os.ReadFile(auditRulesPath)
		hasRules := strings.Contains(string(data), "identity") && strings.Contains(string(data), "sudoers")
		result.Checks = append(result.Checks, Check{
			Name:     "rules configured",
			Status:   boolCheck(hasRules),
			Expected: "configured",
			Actual:   ternary(hasRules, "configured", "missing"),
		})
	}

	return result
}
