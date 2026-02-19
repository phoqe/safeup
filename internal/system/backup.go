package system

import (
	"fmt"
	"io"
	"os"
	"time"
)

func BackupFile(path string) (string, error) {
	src, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("cannot open %s for backup: %w", path, err)
	}
	defer src.Close()

	backupPath := fmt.Sprintf("%s.bak.%s", path, time.Now().Format("20060102-150405"))
	dst, err := os.Create(backupPath)
	if err != nil {
		return "", fmt.Errorf("cannot create backup file %s: %w", backupPath, err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return "", fmt.Errorf("failed to write backup %s: %w", backupPath, err)
	}

	return backupPath, nil
}
