# Troubleshooting

This guide covers common issues encountered with True Protection by Jag and their solutions.

---

## Table of Contents

- [Diagnostic Tool](#diagnostic-tool)
- [Daemon Connection Issues](#daemon-connection-issues)
- [Scanner Issues](#scanner-issues)
- [Firewall Issues](#firewall-issues)
- [JagAI Module Issues](#jagai-module-issues)
- [Update Issues](#update-issues)
- [Performance Issues](#performance-issues)
- [Platform-Specific Issues](#platform-specific-issues)
  - [Windows](#windows)
  - [Linux](#linux)
  - [macOS](#macos)
- [Collecting Logs for Bug Reports](#collecting-logs-for-bug-reports)
- [Getting Help](#getting-help)

---

## Diagnostic Tool

The built-in diagnostic tool checks all components and reports any issues:

```bash
tpj diagnose
```

Example output:

```
True Protection by Jag - System Diagnostics
---
Platform:       linux
Architecture:   x86_64
Daemon:         connected (uptime: 14h 32m)
Firewall:       enabled (eBPF backend)
Scanner:        ready
Real-time:      enabled
HIPS:           enabled
Signatures:     v2026.03.27 (142,587 loaded)
GeoIP:          loaded (v2026.03.25)
AI Module:      active (Professional)
Disk space:     14.2 GB free in /var/lib/true-protection
Config:         valid (/etc/true-protection/config.toml)
IPC endpoint:   /var/run/true-protection/tpj.sock (accessible)
---
Status: All checks passed.
```

If any component shows an error, the diagnostic tool provides details and suggested fixes.

---

## Daemon Connection Issues

### "Daemon is not running"

**Symptom:**
```
Status:     Not connected
            Daemon is not running (socket not found). Start it with: sudo systemctl start tpj-daemon
```

**Solutions:**

1. **Start the daemon:**

   Linux:
   ```bash
   sudo systemctl start tpj-daemon
   ```

   Windows (Administrator PowerShell):
   ```powershell
   net start TrueProtection
   ```

   macOS:
   ```bash
   sudo launchctl load /Library/LaunchDaemons/com.jagjourney.tpj-daemon.plist
   ```

2. **Check daemon logs for crash information:**
   ```bash
   sudo journalctl -u tpj-daemon --no-pager -n 50
   ```

3. **Verify the IPC endpoint exists:**

   Linux/macOS:
   ```bash
   ls -la /var/run/true-protection/tpj.sock
   ```

   Windows:
   ```powershell
   # Check for the named pipe
   [System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String "tpj"
   ```

### "Permission denied" When Running CLI

The `tpj` CLI communicates with the daemon over IPC. Some commands require elevated privileges.

```bash
# Linux/macOS: use sudo for administrative operations
sudo tpj scan --scan-type full

# Windows: run the terminal as Administrator
```

Non-administrative commands like `tpj status` should work without elevation.

---

## Scanner Issues

### "Signature database error"

**Cause:** The signature database file is missing or corrupted.

**Solution:**
```bash
# Remove the corrupt database
sudo rm /var/lib/true-protection/signatures.tpdb

# Force a fresh download
tpj update --apply
```

### Scan Produces No Results

**Possible causes:**

1. **Daemon not running.** Check with `tpj status`.
2. **Exclusion too broad.** Check exclusions with `tpj config --get scanner.exclusions`.
3. **Max file size too low.** Large files may be skipped. Check with `tpj config --get scanner.max_file_size_mb`.

### Scan Takes Too Long

- **Reduce archive depth:** `tpj config --set scanner.max_archive_depth --value 2`
- **Add exclusions** for known-safe large directories (VM images, build caches):
  ```toml
  [scanner]
  exclusions = ["/home/user/VMs", "/var/lib/docker"]
  ```
- **Use quick scan** instead of full scan for routine checks.
- **Check I/O bottlenecks:** The scan speed is usually limited by disk I/O. An SSD dramatically improves scan times.

### False Positives

If a legitimate file is flagged as malicious:

1. Check the detection name and method in the scan results.
2. Verify the file against other analysis tools (e.g., VirusTotal).
3. If confirmed as a false positive:
   - Restore from quarantine: `tpj quarantine restore <id>`
   - Add to exclusions: `tpj config --set scanner.exclusions --value "/path/to/file"`
   - Report the false positive on [GitHub Issues](https://github.com/jagjourney/true-protection-by-jag/issues).

---

## Firewall Issues

### "Firewall: error" Status

**Windows:**
- The WFP callout driver may not be installed or signed correctly.
- Reinstall True Protection as Administrator.
- Check if another security product is conflicting with the WFP driver.

**Linux:**
- Check kernel version: `uname -r` (requires 5.10+ for eBPF support).
- Ensure `libbpf-dev` is installed.
- Check dmesg for eBPF errors: `sudo dmesg | grep -i bpf`

**macOS:**
- Go to **System Settings > Privacy & Security** and approve the Network Extension.
- Restart the daemon after approval.

### Applications Cannot Connect to the Internet

1. Check if the firewall is the cause:
   ```bash
   tpj firewall toggle off
   # Test connectivity
   tpj firewall toggle on
   ```

2. Check for blocking rules:
   ```bash
   tpj firewall list
   ```

3. Check default policies:
   ```bash
   tpj config --get firewall.default_outbound
   ```
   If set to `Block`, you need explicit allow rules for each application.

4. Check geo-blocking:
   ```bash
   tpj config --get firewall.geo_blocking_enabled
   tpj config --get firewall.blocked_countries
   ```

5. View the firewall log for blocked connections:
   ```bash
   tpj log --component firewall --lines 20
   ```

---

## JagAI Module Issues

### "subscription required"

The AI module requires an active subscription. Check your status:

```bash
tpj ai status
```

If you have a subscription, verify the API key is configured:

```bash
tpj config --get ai.enabled
```

### "Daily API quota exhausted"

You have reached your tier's daily scan limit. Options:

- Wait until midnight UTC for the quota to reset.
- Upgrade your subscription tier for a higher limit.
- Check your usage: `tpj ai status`

### "Failed to connect to JagAI API"

- Check internet connectivity.
- Verify the API endpoint: `tpj config --get ai.api_endpoint`
- Check if a firewall or proxy is blocking HTTPS to `api.trueprotection.dev`.
- Check daemon logs: `tpj log --component ai --lines 20`

### "Rate limited (429)"

You are sending too many requests per minute. The client automatically retries with exponential backoff. If this persists, reduce the frequency of AI scans or upgrade your tier.

---

## Update Issues

### "Failed to check for updates"

- Verify internet connectivity.
- Check DNS resolution: `nslookup api.github.com`
- Check if a proxy is configured but not accessible.
- Try manually: `curl -s https://api.github.com/repos/jagjourney/true-protection-by-jag/releases | head -20`

### Signature Updates Not Applying

```bash
# Check current signature version
tpj status

# Force a signature update
tpj update --apply --force

# Check for errors
tpj log --component updater --lines 20
```

---

## Performance Issues

### High CPU Usage

- Check if a scan is running: `tpj status` (look for "Busy" status).
- If real-time scanning is causing issues, temporarily adjust:
  ```bash
  # Reduce max scan threads
  tpj config --set scanner.max_scan_threads --value 2

  # Enable adaptive throttling
  tpj config --set scanner.adaptive_throttling --value true
  ```

### High Memory Usage

- Check the signature database size. Larger databases use more memory.
- If caching is consuming too much RAM, reduce cache sizes:
  ```toml
  [ai]
  cache_max_entries = 5000
  ```

### Slow File Operations

Real-time scanning adds a small delay to file operations. If this is noticeable:

1. Add high-volume directories to exclusions (build output, database files):
   ```toml
   [scanner]
   exclusions = ["/path/to/build-output"]
   ```

2. Disable scan-on-access for non-executable files (reduces scope):
   ```toml
   [scanner]
   scan_on_access = true
   scan_on_write = false  # Only scan on access, not on write
   ```

---

## Platform-Specific Issues

### Windows

**"Access denied" when starting the daemon:**
Run the terminal as Administrator. The daemon requires SYSTEM-level privileges for firewall and real-time scanning.

**WFP driver not loading:**
1. Open Device Manager.
2. Look for "True Protection WFP Callout" under Network adapters.
3. If not present, reinstall the application.
4. If present but showing an error, check that the driver is properly signed.

**Conflict with Windows Defender:**
True Protection can coexist with Windows Defender. However, for optimal performance, consider disabling one or configuring exclusions in both products to avoid scanning each other's files.

### Linux

**"Permission denied: /var/run/true-protection/tpj.sock":**
The IPC socket is owned by root. Use `sudo` for CLI commands, or add your user to the `tpj` group:
```bash
sudo usermod -aG tpj $USER
# Log out and back in for the group change to take effect
```

**eBPF programs not loading (older kernels):**
The firewall requires kernel 5.10+ for eBPF support. On older kernels, the firewall falls back to nftables:
```bash
# Check kernel version
uname -r

# If kernel is too old, the firewall uses nftables backend
# Install nftables if not present:
sudo apt install nftables
```

**SELinux blocking the daemon:**
If SELinux is enforcing, you may need to install the True Protection SELinux policy module:
```bash
sudo semodule -i /usr/share/true-protection/selinux/tpj-daemon.pp
```

### macOS

**"Network Extension not approved":**
1. Open **System Settings > Privacy & Security**.
2. Find the True Protection entry and click **Allow**.
3. Restart the daemon.

**"Full Disk Access required":**
For real-time scanning, grant Full Disk Access:
1. Open **System Settings > Privacy & Security > Full Disk Access**.
2. Add `tpj-daemon`.

---

## Collecting Logs for Bug Reports

When reporting a bug, include diagnostic information:

```bash
# Run full diagnostics
tpj diagnose > /tmp/tpj-diagnose.txt 2>&1

# Export recent logs
tpj log --lines 500 --export /tmp/tpj-logs.json

# Include system information
uname -a >> /tmp/tpj-diagnose.txt
tpj --version >> /tmp/tpj-diagnose.txt
```

Attach these files to your GitHub issue.

---

## Getting Help

1. **Documentation:** [https://docs.trueprotection.dev](https://docs.trueprotection.dev)
2. **GitHub Issues:** [https://github.com/jagjourney/true-protection-by-jag/issues](https://github.com/jagjourney/true-protection-by-jag/issues)
3. **Community Forum:** [https://community.trueprotection.dev](https://community.trueprotection.dev)
4. **Enterprise Support:** Enterprise subscribers have access to dedicated support at [support@trueprotection.dev](mailto:support@trueprotection.dev).

When opening an issue, include:

1. Platform and OS version
2. True Protection version (`tpj --version`)
3. Steps to reproduce the issue
4. Expected vs. actual behavior
5. Diagnostic output (`tpj diagnose`)
6. Relevant logs (`tpj log --export`)
