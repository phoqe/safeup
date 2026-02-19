package modules

import (
	"fmt"
	"strings"

	"github.com/phoqe/safeup/internal/system"
)

type UFWModule struct{}

func (m *UFWModule) Name() string        { return "UFW Firewall" }
func (m *UFWModule) Description() string { return "Configure UFW firewall rules" }

func (m *UFWModule) Apply(cfg *system.UFWConfig) error {
	if !system.IsInstalled("ufw") {
		if err := system.AptInstall("ufw"); err != nil {
			return fmt.Errorf("failed to install ufw: %w", err)
		}
	}

	commands := []string{
		"ufw default deny incoming",
		"ufw default allow outgoing",
	}

	for _, port := range cfg.AllowedPorts {
		commands = append(commands, fmt.Sprintf("ufw allow %s", port))
	}

	if cfg.RateLimitSSH {
		sshPort := "22"
		for _, p := range cfg.AllowedPorts {
			if strings.HasSuffix(p, "/tcp") && (strings.HasPrefix(p, "22") || !strings.Contains(p, "80") && !strings.Contains(p, "443")) {
				sshPort = strings.TrimSuffix(p, "/tcp")
				break
			}
		}
		commands = append(commands, fmt.Sprintf("ufw limit %s/tcp", sshPort))
	}

	commands = append(commands, "ufw --force enable")

	for _, cmd := range commands {
		result, err := system.RunShell(cmd)
		if err != nil {
			return fmt.Errorf("failed: %s: %w", cmd, err)
		}
		if result.ExitCode != 0 {
			return fmt.Errorf("failed: %s: %s", cmd, result.Stderr)
		}
	}

	return nil
}

func (m *UFWModule) Plan(cfg *system.UFWConfig) []string {
	var cmds []string
	cmds = append(cmds, "apt-get install -y ufw")
	cmds = append(cmds, "ufw default deny incoming")
	cmds = append(cmds, "ufw default allow outgoing")
	for _, port := range cfg.AllowedPorts {
		cmds = append(cmds, "ufw allow "+port)
	}
	if cfg.RateLimitSSH {
		sshPort := "22"
		for _, p := range cfg.AllowedPorts {
			if strings.HasSuffix(p, "/tcp") && (strings.HasPrefix(p, "22") || !strings.Contains(p, "80") && !strings.Contains(p, "443")) {
				sshPort = strings.TrimSuffix(p, "/tcp")
				break
			}
		}
		cmds = append(cmds, "ufw limit "+sshPort+"/tcp")
	}
	cmds = append(cmds, "ufw --force enable")
	return cmds
}

func (m *UFWModule) Verify(cfg *system.UFWConfig) *VerifyResult {
	result := &VerifyResult{ModuleName: m.Name()}

	statusResult, err := system.Run("ufw", "status")
	if err != nil {
		result.Checks = append(result.Checks, Check{
			Name:   "ufw accessible",
			Status: StatusFail,
			Actual: err.Error(),
		})
		return result
	}

	statusOutput := statusResult.Stdout
	isActive := strings.Contains(statusOutput, "Status: active")

	result.Checks = append(result.Checks, Check{
		Name:     "enabled",
		Status:   boolCheck(isActive),
		Expected: "active",
		Actual:   ternary(isActive, "active", "inactive"),
	})

	if !isActive {
		return result
	}

	for _, port := range cfg.AllowedPorts {
		portBase := strings.TrimSuffix(port, "/tcp")
		found := strings.Contains(statusOutput, portBase)
		result.Checks = append(result.Checks, Check{
			Name:     fmt.Sprintf("%s allowed", port),
			Status:   boolCheck(found),
			Expected: "ALLOW",
			Actual:   ternary(found, "ALLOW", "not found"),
		})
	}

	return result
}

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}
