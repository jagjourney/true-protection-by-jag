# Getting Started with True Protection by Jag

Welcome to **True Protection by Jag**, an enterprise-grade, cross-platform security suite that combines a stateful deep-packet-inspection firewall, multi-engine antivirus scanner, kernel-level anti-rootkit detector, and AI-powered threat analysis into a single platform.

This guide covers installation and first-run setup for Windows, Linux, and macOS.

---

## Table of Contents

- [System Requirements](#system-requirements)
- [Installation](#installation)
  - [Windows](#windows)
  - [Debian / Ubuntu](#debian--ubuntu)
  - [Fedora / RHEL / CentOS](#fedora--rhel--centos)
  - [Arch Linux](#arch-linux)
  - [macOS](#macos)
- [Verifying the Installation](#verifying-the-installation)
- [First-Run Setup](#first-run-setup)
- [Starting the Daemon](#starting-the-daemon)
- [Running Your First Scan](#running-your-first-scan)
- [Activating JagAI (Optional)](#activating-jagai-optional)
- [Uninstallation](#uninstallation)
- [Next Steps](#next-steps)

---

## System Requirements

| Requirement | Minimum | Recommended |
|---|---|---|
| **OS** | Windows 10 (1903+), Ubuntu 22.04, Fedora 38, macOS 13 | Windows 11, Ubuntu 24.04, Fedora 40, macOS 15 |
| **CPU** | x86_64 or ARM64, 2 cores | 4+ cores |
| **RAM** | 2 GB | 4 GB+ |
| **Disk** | 500 MB free | 2 GB+ free (for quarantine and signature databases) |
| **Network** | Not required for core features | Required for updates, JagAI, and GeoIP databases |

**Administrator/root privileges** are required for installation and for the daemon to access kernel-level protection features (firewall, real-time file monitoring, rootkit scanning).

---

## Installation

### Windows

**Option A: MSI Installer (Recommended)**

1. Download the latest `.msi` installer from the [GitHub Releases](https://github.com/jagjourney/true-protection-by-jag/releases) page.
2. Right-click the installer and select **Run as administrator**.
3. Follow the installation wizard. The default installation directory is `C:\Program Files\True Protection`.
4. The installer registers the `tpj-daemon` as a Windows service and adds `tpj` to your system PATH.

**Option B: winget**

```powershell
winget install JagJourney.TrueProtection
```

**Option C: Chocolatey**

```powershell
choco install true-protection
```

After installation, the daemon starts automatically as a Windows service.

### Debian / Ubuntu

```bash
# 1. Import the GPG signing key
curl -fsSL https://repo.trueprotection.dev/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/trueprotection.gpg

# 2. Add the APT repository
echo "deb [signed-by=/usr/share/keyrings/trueprotection.gpg] https://repo.trueprotection.dev/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/trueprotection.list

# 3. Update and install
sudo apt update
sudo apt install true-protection
```

The package installs a systemd service that starts automatically:

```bash
sudo systemctl status tpj-daemon
```

### Fedora / RHEL / CentOS

```bash
# 1. Add the repository
sudo dnf config-manager --add-repo https://repo.trueprotection.dev/rpm/trueprotection.repo

# 2. Install
sudo dnf install true-protection
```

### Arch Linux

True Protection is available from the AUR:

```bash
yay -S true-protection
```

Or manually:

```bash
git clone https://aur.archlinux.org/true-protection.git
cd true-protection
makepkg -si
```

### macOS

**Option A: Homebrew (Recommended)**

```bash
brew install --cask true-protection
```

**Option B: PKG Installer**

Download the `.pkg` installer from [GitHub Releases](https://github.com/jagjourney/true-protection-by-jag/releases) and open it. macOS will prompt you to approve the Network Extension in **System Settings > Privacy & Security**.

**Important:** On macOS, you must grant Full Disk Access to True Protection in **System Settings > Privacy & Security > Full Disk Access** for real-time scanning to work properly.

---

## Verifying the Installation

After installation, open a terminal and run:

```bash
tpj --version
```

Expected output:

```
tpj 0.1.0
```

To check that the daemon is running and all components are operational:

```bash
tpj status
```

Expected output:

```
True Protection by Jag v0.1.0
---
Status:     Active
Firewall:   enabled
Scanner:    ready
Real-time:  enabled
HIPS:       enabled
Signatures: v2026.03.27 (142,587 signatures)
AI Module:  not configured
Uptime:     0h 2m 15s
```

If you see `Status: Not connected`, the daemon is not running. See [Starting the Daemon](#starting-the-daemon) below.

---

## First-Run Setup

On first launch, True Protection applies a sensible default configuration:

| Setting | Default Value |
|---|---|
| Real-time scanning | Enabled |
| Scan on file access | Enabled |
| Scan on file write | Enabled |
| Scan archives | Enabled (up to 5 levels deep) |
| Max file size for scanning | 512 MB |
| Firewall | Enabled |
| Default inbound policy | Block (deny by default) |
| Default outbound policy | Allow |
| Stealth mode | Disabled |
| Geo-blocking | Disabled |
| Auto-update | Enabled |
| Update channel | Stable |
| Signature check interval | Every 4 hours |
| Application update check | Every 12 hours |
| JagAI module | Disabled (requires subscription) |

To modify any setting, use the CLI:

```bash
# View a setting
tpj config --get scanner.realtime_enabled

# Change a setting
tpj config --set scanner.max_file_size_mb --value 1024
```

Or edit the configuration file directly. See the [Configuration Reference](../admin-guide/configuration.md) for the full list of options.

### Configuration File Locations

| Platform | Config File Path |
|---|---|
| **Windows** | `C:\ProgramData\TrueProtection\config.toml` |
| **Linux** | `/etc/true-protection/config.toml` |
| **macOS** | `/Library/Application Support/TrueProtection/config.toml` |

### Data Directories

| Platform | Data Directory | Quarantine Directory |
|---|---|---|
| **Windows** | `C:\ProgramData\TrueProtection\` | `C:\ProgramData\TrueProtection\Quarantine\` |
| **Linux** | `/var/lib/true-protection/` | `/var/lib/true-protection/quarantine/` |
| **macOS** | `/Library/Application Support/TrueProtection/` | `/Library/Application Support/TrueProtection/Quarantine/` |

---

## Starting the Daemon

The core protection daemon (`tpj-daemon`) must be running for all features to work. The CLI tool communicates with the daemon over IPC (named pipes on Windows, Unix domain sockets on Linux/macOS).

### Windows

The daemon is installed as a Windows service and starts automatically at boot.

```powershell
# Check service status
sc query TrueProtection

# Start manually (requires Administrator)
net start TrueProtection

# Stop
net stop TrueProtection
```

### Linux

```bash
# Start and enable at boot
sudo systemctl enable --now tpj-daemon

# Check status
sudo systemctl status tpj-daemon

# View daemon logs
sudo journalctl -u tpj-daemon -f
```

### macOS

```bash
# Load and start the daemon
sudo launchctl load /Library/LaunchDaemons/com.jagjourney.tpj-daemon.plist

# Check if running
sudo launchctl list | grep tpj

# Unload
sudo launchctl unload /Library/LaunchDaemons/com.jagjourney.tpj-daemon.plist
```

---

## Running Your First Scan

Once the daemon is running, start with a quick scan to verify everything works:

```bash
tpj scan --scan-type quick
```

This scans common locations where malware is typically found (startup directories, temp folders, running processes, and recently modified files). A quick scan typically completes in under a minute.

For a comprehensive check of your entire system:

```bash
tpj scan --scan-type full
```

To scan specific directories:

```bash
tpj scan --scan-type custom /path/to/folder1 /path/to/folder2
```

After a scan completes, you will see a summary:

```
Scan completed (ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890)
---
Files scanned:  12,847
Files clean:    12,845
Files skipped:  0
Threats found:  2

--- Threats ---
  1. [Critical] Trojan.GenericKD.48291537 - /tmp/suspicious.exe (quarantined)
  2. [High] Rootkit.ZeroAccess.C - /var/tmp/.hidden (quarantined)

Run 'tpj quarantine list' to see quarantined items.
```

For full details on scan types and result interpretation, see the [Scanning Guide](scanning.md).

---

## Activating JagAI (Optional)

The JagAI module provides AI-powered threat analysis, automated incident response, and proactive threat hunting. It requires an active subscription.

1. Visit [https://trueprotection.dev/pricing](https://trueprotection.dev/pricing) and choose a plan.
2. After subscribing, you will receive an API key.
3. Configure the API key:

```bash
# Set your subscription API key (stored encrypted on disk)
tpj config --set ai.api_key --value "tpj_key_xxxxxxxxxxxxxxxxxxxx"

# Enable the AI module
tpj config --set ai.enabled --value true
```

4. Verify activation:

```bash
tpj ai status
```

Expected output:

```
JagAI Module: active
Tier:         Professional
Scans today:  0 / 1,000
API endpoint: https://api.trueprotection.dev/v1
```

See the [JagAI Module Guide](jagai-module.md) for full details on AI features.

---

## Uninstallation

### Windows

Use **Settings > Apps > True Protection by Jag > Uninstall**, or run:

```powershell
msiexec /x {ProductCode}
```

### Debian / Ubuntu

```bash
sudo apt remove true-protection
# To also remove configuration files:
sudo apt purge true-protection
```

### Fedora / RHEL

```bash
sudo dnf remove true-protection
```

### Arch Linux

```bash
sudo pacman -Rns true-protection
```

### macOS

```bash
brew uninstall --cask true-protection
```

Or run the uninstaller at `/Library/Application Support/TrueProtection/Uninstall.app`.

---

## Next Steps

- [Understanding the Dashboard](dashboard.md) - Learn what each status indicator means
- [Scanning Guide](scanning.md) - Deep dive into scan types, scheduling, and results
- [Firewall Configuration](firewall.md) - Set up rules, application control, and geo-blocking
- [JagAI Module](jagai-module.md) - Explore AI-powered threat analysis
- [CLI Reference](../admin-guide/cli-reference.md) - Complete command reference
- [Configuration Reference](../admin-guide/configuration.md) - All configuration options explained
