# Auto-Updates, Signature Updates, and Channels

True Protection by Jag uses two independent update mechanisms: **application updates** (new program versions) and **signature updates** (malware detection database). Both are delivered through the GitHub Releases infrastructure and verified with cryptographic signatures.

---

## Table of Contents

- [Checking for Updates](#checking-for-updates)
- [Application Updates](#application-updates)
- [Signature Updates](#signature-updates)
- [Update Channels](#update-channels)
- [Auto-Update Configuration](#auto-update-configuration)
- [Manual Updates](#manual-updates)
- [Critical and Security Updates](#critical-and-security-updates)
- [Update Verification and Signing](#update-verification-and-signing)
- [Offline Environments](#offline-environments)
- [Configuration Reference](#configuration-reference)
- [Troubleshooting Updates](#troubleshooting-updates)

---

## Checking for Updates

```bash
tpj update
```

Example output:

```
Checking for updates...
Current version:     0.1.0
Latest version:      0.2.0
Signatures version:  v2026.03.27 (142,587 signatures)

An update is available: 0.1.0 -> 0.2.0

Run 'tpj update --apply' to download and install.
```

For JSON output:

```bash
tpj update --format json
```

---

## Application Updates

Application updates include new features, bug fixes, performance improvements, and security patches for the True Protection engine itself.

### How Application Updates Work

1. The daemon periodically queries the [GitHub Releases API](https://api.github.com/repos/jagjourney/true-protection-by-jag/releases) for new versions.
2. Releases are filtered by your configured update channel (Stable, Beta, or Canary).
3. The version tag is compared against the currently installed version using semantic versioning.
4. If a newer version is available, the user is notified through the dashboard/tray and CLI.
5. When the user approves, the update package is downloaded, its Ed25519 signature is verified, and the update is applied.

### Applying Updates

```bash
# Check and apply in one step
tpj update --apply
```

On Windows, the update is applied by the Windows service during a restart. On Linux, the package manager update mechanism is used. On macOS, the application restarts with the new version.

### Force Reinstall

If you need to reinstall the current version (e.g., after a corrupted installation):

```bash
tpj update --apply --force
```

---

## Signature Updates

Signature updates provide new malware detection patterns, hash lists, YARA rules, and heuristic analysis rules. Signature updates are independent of application updates and are released much more frequently.

### How Signature Updates Work

1. The daemon checks for new signature databases on a configurable interval (default: every 4 hours).
2. Signature updates are delivered as delta packages (only new signatures since the last update) for efficiency.
3. The signature package is verified using Ed25519 signatures before being loaded.
4. The new signatures are hot-loaded into the running engine without requiring a restart.
5. A `SignaturesUpdated` event is published to the event bus.

### Checking Signature Status

```bash
tpj status
```

Look for the Signatures line:

```
Signatures: v2026.03.27 (142,587 signatures)
```

After an update:

```
Signature database updated (+1,245 new signatures).
```

---

## Update Channels

True Protection supports three update channels, each with a different stability guarantee:

| Channel | Description | Release Cadence | Risk Level |
|---|---|---|---|
| **Stable** | Thoroughly tested releases. Recommended for production. | Every 2-4 weeks | Very low |
| **Beta** | Pre-release versions with new features. May contain minor bugs. | Weekly | Low-moderate |
| **Canary** | Bleeding-edge builds. May be unstable. For testing and development only. | Daily or on-demand | Higher |

### Changing Your Update Channel

```bash
# Switch to beta channel
tpj config --set updater.update_channel --value Beta

# Switch to canary channel
tpj config --set updater.update_channel --value Canary

# Switch back to stable
tpj config --set updater.update_channel --value Stable
```

In `config.toml`:

```toml
[updater]
update_channel = "Stable"  # Stable, Beta, or Canary
```

### Channel Selection Logic

- **Stable** channel only sees releases where `prerelease` is `false` on GitHub.
- **Beta** channel sees all releases (including pre-releases).
- **Canary** channel sees all releases including nightly builds and release candidates.

Signature updates are not affected by the update channel - all channels receive the latest signatures on the same schedule.

---

## Auto-Update Configuration

### Automatic Update Checks

By default, True Protection checks for updates automatically:

| Check Type | Default Interval | Configurable |
|---|---|---|
| Application updates | Every 12 hours | `updater.check_interval_hours` |
| Signature updates | Every 4 hours | `updater.signature_check_interval_hours` |

### Disabling Auto-Updates

```bash
# Disable automatic update checks
tpj config --set updater.auto_update --value false
```

When auto-updates are disabled, you must manually check and apply updates:

```bash
tpj update          # Check only
tpj update --apply  # Check and apply
```

**Warning:** Disabling auto-updates means your signature database will become stale, reducing protection against new threats. This is not recommended for production systems.

### Auto-Apply Updates

For hands-free operation (recommended for servers):

```toml
[updater]
auto_update = true
auto_apply = true               # Automatically apply available updates
auto_apply_signatures = true    # Always auto-apply signature updates (default)
auto_apply_critical = true      # Automatically apply critical/security updates
auto_apply_non_critical = false # Prompt for non-critical application updates
```

---

## Manual Updates

### Download and Apply Manually

For air-gapped or restricted environments, you can download update packages manually:

1. Visit [https://github.com/jagjourney/true-protection-by-jag/releases](https://github.com/jagjourney/true-protection-by-jag/releases).
2. Download the appropriate package for your platform.
3. Transfer the package to the target system.
4. Install using the platform package manager:

**Windows:**
```powershell
msiexec /i TrueProtection-0.2.0-x64.msi
```

**Debian/Ubuntu:**
```bash
sudo dpkg -i true-protection_0.2.0_amd64.deb
```

**Fedora/RHEL:**
```bash
sudo rpm -U true-protection-0.2.0-1.x86_64.rpm
```

**macOS:**
```bash
sudo installer -pkg TrueProtection-0.2.0.pkg -target /
```

### Manual Signature Updates

Signature database files can also be downloaded manually and placed in the data directory:

```bash
# Download the latest signature database
curl -o /tmp/tpj-signatures-latest.tpdb \
  https://sigs.trueprotection.dev/latest/signatures.tpdb

# Copy to the data directory
sudo cp /tmp/tpj-signatures-latest.tpdb /var/lib/true-protection/signatures.tpdb

# Trigger a reload
tpj config --set signatures.reload --value true
```

---

## Critical and Security Updates

Updates tagged with `[CRITICAL]` or `[SECURITY]` in the release notes are treated with higher urgency:

- **Desktop:** A prominent banner appears in the dashboard.
- **CLI:** A warning is shown whenever any `tpj` command is run.
- **Tray icon:** The icon changes to red/orange to indicate an urgent update.
- **Auto-apply:** If `auto_apply_critical` is enabled, critical updates are applied automatically.

```
*** CRITICAL UPDATE AVAILABLE ***
A security-critical update is available. Please update immediately.
Run 'tpj update --apply' to download and install.
```

---

## Update Verification and Signing

All update packages are cryptographically signed to prevent tampering:

| Component | Signing Method |
|---|---|
| Application binaries (Windows) | Authenticode EV code signing certificate |
| Application packages (Linux) | GPG signature (key: `repo.trueprotection.dev/gpg.key`) |
| Application packages (macOS) | Apple Developer ID notarization |
| Signature database files | Ed25519 signature (public key embedded in the engine) |
| Update metadata | Ed25519 signature |

The update process verifies:

1. The package signature matches the embedded public key.
2. The SHA-256 hash of the downloaded package matches the published hash.
3. The package version is newer than the installed version (unless `--force` is used).

If any verification step fails, the update is rejected and an error is logged.

---

## Offline Environments

For systems without internet access:

1. **Use a local mirror.** Configure the update URL to point to an internal server:
   ```toml
   [updater]
   github_releases_url = "https://internal-mirror.example.com/api/releases"
   ```

2. **Manual transfer.** Download packages on a connected machine and transfer them via USB or internal network.

3. **Enterprise deployment.** Use SCCM, Ansible, or other deployment tools to push updates. See the [Deployment Guide](../admin-guide/deployment.md).

---

## Configuration Reference

```toml
[updater]
# Enable automatic update checking
auto_update = true

# Update channel: Stable, Beta, or Canary
update_channel = "Stable"

# How often to check for application updates (hours)
check_interval_hours = 12

# How often to check for signature updates (hours)
signature_check_interval_hours = 4

# GitHub Releases API URL (can be overridden for enterprise mirrors)
github_releases_url = "https://api.github.com/repos/jagjourney/true-protection-by-jag/releases"

# Auto-apply settings
auto_apply = false
auto_apply_signatures = true
auto_apply_critical = true
auto_apply_non_critical = false
```

---

## Troubleshooting Updates

### "Failed to check for updates"

- Verify internet connectivity: `ping api.github.com`
- Check if the daemon is running: `tpj status`
- Check firewall rules for outbound HTTPS to `api.github.com`
- Try a manual check: `tpj update --verbose`

### "Signature database error"

- The signature file may be corrupted. Delete it and trigger a fresh download:
  ```bash
  sudo rm /var/lib/true-protection/signatures.tpdb
  tpj update
  ```

### Updates Stuck at "Downloading"

- Check available disk space in the data directory.
- Check for proxy or firewall interference.
- View daemon logs for errors: `tpj log --component updater --lines 20`
