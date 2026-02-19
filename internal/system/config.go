package system

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const ConfigDir = "/etc/safeup"

var ConfigPath = "/etc/safeup/config.json"

type SavedConfig struct {
	User     *UserConfig     `json:"user,omitempty" yaml:"user,omitempty"`
	SSH      *SSHConfig      `json:"ssh,omitempty" yaml:"ssh,omitempty"`
	UFW      *UFWConfig      `json:"ufw,omitempty" yaml:"ufw,omitempty"`
	Fail2Ban *Fail2BanConfig `json:"fail2ban,omitempty" yaml:"fail2ban,omitempty"`
	Upgrades *UpgradesConfig `json:"upgrades,omitempty" yaml:"upgrades,omitempty"`
	Sysctl   *SysctlConfig   `json:"sysctl,omitempty" yaml:"sysctl,omitempty"`
	AppArmor *AppArmorConfig `json:"apparmor,omitempty" yaml:"apparmor,omitempty"`
	Shm      *ShmConfig      `json:"shm,omitempty" yaml:"shm,omitempty"`
	Auditd   *AuditdConfig   `json:"auditd,omitempty" yaml:"auditd,omitempty"`
	Timesync *TimesyncConfig `json:"timesync,omitempty" yaml:"timesync,omitempty"`
}

type UserConfig struct {
	Username         string `json:"username" yaml:"username"`
	AuthorizedKey    string `json:"authorized_key,omitempty" yaml:"authorized_key,omitempty"`
	PasswordlessSudo bool   `json:"passwordless_sudo" yaml:"passwordless_sudo"`
	Password         string `json:"-" yaml:"-"`
}

type SSHConfig struct {
	DisableRootLogin    bool   `json:"disable_root_login" yaml:"disable_root_login"`
	DisablePasswordAuth bool   `json:"disable_password_auth" yaml:"disable_password_auth"`
	Port                string `json:"port" yaml:"port"`
	AuthorizedKey       string `json:"authorized_key,omitempty" yaml:"authorized_key,omitempty"`
	AuthorizedKeyUser   string `json:"authorized_key_user,omitempty" yaml:"authorized_key_user,omitempty"`
}

type UFWConfig struct {
	AllowedPorts []string `json:"allowed_ports" yaml:"allowed_ports"`
	RateLimitSSH bool     `json:"rate_limit_ssh" yaml:"rate_limit_ssh"`
	SSHPort      string   `json:"ssh_port,omitempty" yaml:"ssh_port,omitempty"`
}

type Fail2BanConfig struct {
	MaxRetry int    `json:"max_retry" yaml:"max_retry"`
	BanTime  int    `json:"ban_time" yaml:"ban_time"`
	SSHPort  string `json:"ssh_port,omitempty" yaml:"ssh_port,omitempty"`
}

type UpgradesConfig struct{}

type SysctlConfig struct{}

type AppArmorConfig struct{}

type ShmConfig struct{}

type AuditdConfig struct{}

type TimesyncConfig struct{}

func LoadConfig() (*SavedConfig, error) {
	data, err := os.ReadFile(ConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var cfg SavedConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func SaveConfig(cfg *SavedConfig) error {
	if err := os.MkdirAll(filepath.Dir(ConfigPath), 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(ConfigPath, data, 0600)
}
