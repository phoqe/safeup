package modules

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/phoqe/safeup/internal/system"
)

const fstabPath = "/etc/fstab"
const shmMountPoint = "/dev/shm"
const shmOptions = "defaults,noexec,nosuid,nodev"
const shmEntry = "tmpfs " + shmMountPoint + " tmpfs " + shmOptions + " 0 0"

type ShmModule struct{}

func (m *ShmModule) Name() string        { return "/dev/shm Hardening" }
func (m *ShmModule) Description() string { return "Mount /dev/shm with noexec,nosuid,nodev" }

func (m *ShmModule) Apply(cfg *system.ShmConfig) error {
	data, err := os.ReadFile(fstabPath)
	if err != nil {
		return fmt.Errorf("cannot read fstab: %w", err)
	}

	content := string(data)
	shmRe := regexp.MustCompile(`(?m)^(\s*(?:none|tmpfs)\s+(?:/dev/shm|/run/shm)\s+tmpfs\s+)[^\s]+(\s+\d+\s+\d+\s*)$`)
	if shmRe.MatchString(content) {
		content = shmRe.ReplaceAllString(content, "${1}"+shmOptions+"${2}")
	} else {
		if !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		content += shmEntry + "\n"
	}

	if err := os.WriteFile(fstabPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("cannot write fstab: %w", err)
	}

	result, err := system.Run("mount", "-o", "remount", shmMountPoint)
	if err != nil {
		return fmt.Errorf("remount failed: %w", err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("remount failed: %s", result.Stderr)
	}

	return nil
}

func (m *ShmModule) Verify(cfg *system.ShmConfig) *VerifyResult {
	result := &VerifyResult{ModuleName: m.Name()}

	mountData, err := os.ReadFile("/proc/mounts")
	if err != nil {
		result.Checks = append(result.Checks, Check{
			Name:   "mount options",
			Status: StatusFail,
			Actual: "cannot read mounts",
		})
		return result
	}

	scanner := bufio.NewScanner(strings.NewReader(string(mountData)))
	var hasNoexec, hasNosuid, hasNodev bool
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		if fields[1] == shmMountPoint || fields[1] == "/run/shm" {
			opts := strings.Split(fields[3], ",")
			for _, o := range opts {
				switch o {
				case "noexec":
					hasNoexec = true
				case "nosuid":
					hasNosuid = true
				case "nodev":
					hasNodev = true
				}
			}
			break
		}
	}

	ok := hasNoexec && hasNosuid && hasNodev
	result.Checks = append(result.Checks, Check{
		Name:     "noexec,nosuid,nodev",
		Status:   boolCheck(ok),
		Expected: "all set",
		Actual:   fmt.Sprintf("noexec=%v nosuid=%v nodev=%v", hasNoexec, hasNosuid, hasNodev),
	})

	return result
}
