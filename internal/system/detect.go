package system

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strings"
)

type OSInfo struct {
	ID            string
	VersionID     string
	PrettyName    string
}

func DetectOS() (*OSInfo, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("safeup only supports Linux, detected %s", runtime.GOOS)
	}

	f, err := os.Open("/etc/os-release")
	if err != nil {
		return nil, fmt.Errorf("cannot read /etc/os-release: %w", err)
	}
	defer f.Close()

	info := &OSInfo{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		val = strings.Trim(val, "\"")
		switch key {
		case "ID":
			info.ID = val
		case "VERSION_ID":
			info.VersionID = val
		case "PRETTY_NAME":
			info.PrettyName = val
		}
	}

	if info.ID != "ubuntu" {
		return info, fmt.Errorf("safeup currently supports Ubuntu only, detected %s", info.PrettyName)
	}

	return info, nil
}

func RequireRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("safeup must be run as root — try: sudo safeup")
	}
	return nil
}
