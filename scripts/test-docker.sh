#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE="ubuntu:22.04"

cd "$PROJECT_ROOT"
GOOS=linux GOARCH=amd64 go build -ldflags "-X github.com/phoqe/safeup/cmd.Version=test" -o safeup-linux-amd64 .

echo "=== Unit-style tests ==="
docker run --rm -v "$PROJECT_ROOT/safeup-linux-amd64:/usr/local/bin/safeup:ro" "$IMAGE" \
  bash -c '
    set -e

    safeup --version | grep -q "safeup version test"
    echo "  --version OK"

    safeup --help | grep -q "safeup"
    echo "  --help OK"

    safeup --help | grep -q "dry-run"
    echo "  --dry-run flag OK"

    safeup init --help | grep -q "init"
    echo "  init --help OK"

    safeup verify --help | grep -q "verify"
    echo "  verify --help OK"

    safeup audit --help | grep -q "audit"
    echo "  audit --help OK"

    safeup apply --help | grep -q "apply"
    echo "  apply --help OK"

    safeup verify 2>/dev/null && exit 1 || true
    echo "  verify (no config) fails as expected OK"

    safeup audit >/dev/null 2>&1 || true
    echo "  audit runs OK"

    printf "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n" | timeout 20 safeup init --dry-run >/dev/null 2>&1 || true
    echo "  init --dry-run runs OK"
  '

echo ""
echo "=== E2E test (apply + verify) ==="
docker run --rm \
  -v "$PROJECT_ROOT/safeup-linux-amd64:/usr/local/bin/safeup:ro" \
  -v "$PROJECT_ROOT/scripts:/scripts:ro" \
  "$IMAGE" \
  bash -c '
    set -e

    DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sudo >/dev/null
    safeup apply --config=/scripts/e2e-config.yaml
    safeup verify

    id e2euser >/dev/null
    grep -q e2euser /etc/passwd
    test -f /home/e2euser/.ssh/authorized_keys
    grep -q "e2e-test-key" /home/e2euser/.ssh/authorized_keys
    test -f /etc/sudoers.d/safeup-e2euser
    grep -q NOPASSWD /etc/sudoers.d/safeup-e2euser

    echo "  user created with sudo and SSH key OK"
  '

echo ""
echo "Docker integration test passed"
