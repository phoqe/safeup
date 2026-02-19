package system

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSaveConfig(t *testing.T) {
	dir := t.TempDir()
	origPath := ConfigPath
	ConfigPath = filepath.Join(dir, "config.json")
	defer func() { ConfigPath = origPath }()

	cfg := &SavedConfig{
		User: &UserConfig{Username: "deploy", PasswordlessSudo: true},
		SSH:  &SSHConfig{Port: "2222", DisableRootLogin: true},
	}
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}

	loaded, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if loaded.User == nil || loaded.User.Username != "deploy" {
		t.Errorf("LoadConfig() User = %v, want Username=deploy", loaded.User)
	}
	if loaded.SSH == nil || loaded.SSH.Port != "2222" {
		t.Errorf("LoadConfig() SSH = %v, want Port=2222", loaded.SSH)
	}
}

func TestLoadConfigNotExist(t *testing.T) {
	dir := t.TempDir()
	origPath := ConfigPath
	ConfigPath = filepath.Join(dir, "nonexistent.json")
	defer func() { ConfigPath = origPath }()

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if cfg != nil {
		t.Errorf("LoadConfig() = %v, want nil for missing file", cfg)
	}
}

func TestSaveConfigCreatesDir(t *testing.T) {
	dir := t.TempDir()
	origPath := ConfigPath
	ConfigPath = filepath.Join(dir, "subdir", "config.json")
	defer func() { ConfigPath = origPath }()

	cfg := &SavedConfig{}
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}
	if _, err := os.Stat(ConfigPath); os.IsNotExist(err) {
		t.Errorf("SaveConfig() did not create file at %s", ConfigPath)
	}
}
