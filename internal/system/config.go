package system

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const ConfigDir = "/etc/safeup"
const ConfigPath = "/etc/safeup/config.json"

type SavedConfig struct {
	SSH      *SSHConfig      `json:"ssh,omitempty"`
	UFW      *UFWConfig      `json:"ufw,omitempty"`
	Fail2Ban *Fail2BanConfig `json:"fail2ban,omitempty"`
	Upgrades *UpgradesConfig `json:"upgrades,omitempty"`
}

type SSHConfig struct {
	DisableRootLogin    bool   `json:"disable_root_login"`
	DisablePasswordAuth bool   `json:"disable_password_auth"`
	Port                string `json:"port"`
}

type UFWConfig struct {
	AllowedPorts []string `json:"allowed_ports"`
	RateLimitSSH bool     `json:"rate_limit_ssh"`
}

type Fail2BanConfig struct {
	MaxRetry int `json:"max_retry"`
	BanTime  int `json:"ban_time"`
}

type UpgradesConfig struct {
	AutoReboot bool   `json:"auto_reboot"`
	RebootTime string `json:"reboot_time"`
}

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
