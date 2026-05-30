# Privileged Nmap Mode

Some Nmap presets need elevated privileges:

- OS info (`-O`)
- SYN scan (`-sS`)

The dashboard never runs the full backend as root. Instead, privileged mode only
wraps those fixed Nmap presets with `sudo -n`, after the backend has already
validated the target as an IP address or domain and the user has confirmed
authorization.

## Enable in the Backend

Set these values in `backend/.env`:

```bash
NMAP_PATH=/opt/homebrew/bin/nmap
NMAP_USE_SUDO=true
NMAP_SUDO_PATH=/usr/bin/sudo
```

Use `which nmap` if your Nmap binary is in a different location.

## macOS Passwordless Sudo Rule

Recommended setup from the repo root:

```bash
./scripts/enable-nmap-sudo.sh
```

The script validates the sudoers rule before installing it.

Manual setup:

Create a sudoers drop-in that allows your local user to run the Nmap binary
without a password:

```bash
echo "$USER ALL=(root) NOPASSWD: /opt/homebrew/bin/nmap" | sudo tee /etc/sudoers.d/cloud-threat-intel-nmap
sudo chmod 440 /etc/sudoers.d/cloud-threat-intel-nmap
sudo visudo -cf /etc/sudoers.d/cloud-threat-intel-nmap
```

If `which nmap` returns a different path, replace `/opt/homebrew/bin/nmap`.

## Safety Notes

Only enable this for a local demo or a locked-down environment. Do not expose a
backend with privileged Nmap mode to the public internet. Keep the dashboard's
authorization checkbox and target validation in place.
