#!/usr/bin/env bash
set -euo pipefail

REPO="phoqe/safeup"
INSTALL_DIR="/usr/local/bin"
BINARY="safeup"

main() {
    if [ "$(uname -s)" != "Linux" ]; then
        echo "Error: safeup only supports Linux." >&2
        exit 1
    fi

    if [ "$(id -u)" -ne 0 ]; then
        echo "Error: this installer must be run as root." >&2
        echo "Try: curl -fsSL https://raw.githubusercontent.com/${REPO}/master/install.sh | sudo bash" >&2
        exit 1
    fi

    ARCH="$(uname -m)"
    case "${ARCH}" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *)
            echo "Error: unsupported architecture ${ARCH}" >&2
            exit 1
            ;;
    esac

    DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/safeup-linux-${ARCH}"

    echo "Downloading safeup for linux/${ARCH}..."
    if command -v curl &>/dev/null; then
        curl -fsSL -o "${INSTALL_DIR}/${BINARY}" "${DOWNLOAD_URL}"
    elif command -v wget &>/dev/null; then
        wget -qO "${INSTALL_DIR}/${BINARY}" "${DOWNLOAD_URL}"
    else
        echo "Error: curl or wget is required." >&2
        exit 1
    fi

    chmod +x "${INSTALL_DIR}/${BINARY}"
    echo "Installed safeup to ${INSTALL_DIR}/${BINARY}"
    echo ""
    echo "Get started:"
    echo "  safeup init    - Interactively harden this server"
    echo "  safeup apply   - Apply config from file (safeup apply -c config.yaml)"
    echo "  safeup verify  - Check hardening against saved config"
    echo "  safeup audit   - Scan for security concerns (no config required)"
    echo ""
}

main
