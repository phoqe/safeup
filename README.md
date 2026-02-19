# SafeUp

Interactive VPS hardening for Ubuntu. Run once on a fresh server to lock it down.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/phoqe/safeup/master/install.sh | sudo bash
```

Requires root and Linux (amd64 or arm64). The installer downloads the binary to `/usr/local/bin/safeup`.

## Commands

| Command | Description |
|---------|-------------|
| `safeup init` | Interactive wizard to harden the server |
| `safeup verify` | Check configuration matches expected state |
| `safeup audit` | Scan for security issues (no config required) |
| `safeup apply -c config.yaml` | Apply config from file (non-interactive) |

## Features

- **Create User** — Non-root user with sudo (password required) and SSH key
- **SSH Hardening** — Disable root login, password auth, custom port, X11/TCP forwarding off, AllowUsers
- **UFW Firewall** — Deny incoming by default, allow specified ports, rate-limit SSH
- **fail2ban** — Brute-force protection for SSH
- **Kernel Hardening** — sysctl (rp_filter, syncookies, ASLR, etc.)
- **AppArmor** — Ensure enabled and enforcing
- **/dev/shm Hardening** — noexec, nosuid, nodev
- **auditd** — Audit logging for auth and sudo
- **Time Sync** — systemd-timesyncd, chrony, or ntp
- **Unattended Upgrades** — Automatic security updates

## Config Format

`safeup apply` accepts JSON or YAML:

```yaml
user:
  username: deploy
  authorized_key: "ssh-ed25519 AAAAC3..."

ssh:
  disable_root_login: true
  disable_password_auth: true
  port: "2222"

upgrades: {}
```

## Development

```bash
make test          # Unit tests
make test-docker   # E2E tests (requires Docker)
make build         # Build linux/amd64 and linux/arm64
```
