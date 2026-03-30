# Scanning Guide

True Protection by Jag provides multiple scan modes designed for different situations, from quick spot-checks to deep forensic scans. This guide explains every scan type, how to configure and run them, and how to interpret the results.

---

## Table of Contents

- [Scan Types Overview](#scan-types-overview)
- [Running Scans](#running-scans)
  - [Quick Scan](#quick-scan)
  - [Full Scan](#full-scan)
  - [Custom Scan](#custom-scan)
  - [Rootkit Scan](#rootkit-scan)
  - [Memory Scan](#memory-scan)
  - [Boot Scan](#boot-scan)
- [Real-Time (On-Access) Scanning](#real-time-on-access-scanning)
- [Detection Engines](#detection-engines)
- [Interpreting Scan Results](#interpreting-scan-results)
- [Scan Exclusions](#scan-exclusions)
- [Scheduled Scans](#scheduled-scans)
- [Performance Tuning](#performance-tuning)
- [Scanning Archives and Compressed Files](#scanning-archives-and-compressed-files)
- [EICAR Test File](#eicar-test-file)

---

## Scan Types Overview

| Scan Type | Target | Duration | Use Case |
|---|---|---|---|
| **Quick** | Common malware locations, running processes, startup items | ~1 minute | Daily check or when you suspect an issue |
| **Full** | Entire filesystem | 30 min - 2+ hours | Weekly deep scan, post-infection verification |
| **Custom** | User-specified paths | Varies | Scan a specific directory, external drive, or downloaded file |
| **Rootkit** | Kernel objects, hidden processes, driver integrity, MBR/VBR | 5--15 minutes | Suspected rootkit or system compromise |
| **Memory** | Running processes and loaded modules in RAM | 2--5 minutes | Detect fileless malware and in-memory threats |
| **Boot** | Runs at next system boot, before the OS fully loads | 5--20 minutes | Scan locked files and MBR/VBR sectors that cannot be accessed at runtime |

---

## Running Scans

All scans are initiated via the `tpj scan` command. The CLI sends the request to the daemon over IPC, and the daemon orchestrates the scan using all available detection engines.

### Quick Scan

```bash
tpj scan --scan-type quick
```

The quick scan targets:

- Running processes and their loaded modules
- System startup locations (registry Run keys on Windows, systemd units on Linux, LaunchAgents on macOS)
- User temp directories
- Recent downloads folders
- Browser cache and extension directories
- Files modified in the last 24 hours in common locations

### Full Scan

```bash
tpj scan --scan-type full
```

Scans every file on all mounted filesystems (excluding configured exclusions). This is the most thorough scan type. Consider running it:

- Weekly as part of a maintenance routine
- After recovering from a suspected compromise
- After installing True Protection for the first time

**Tip:** Full scans can be resource-intensive. Use `--verbose` to monitor progress in real time:

```bash
tpj scan --scan-type full --verbose
```

### Custom Scan

```bash
# Scan a single directory
tpj scan --scan-type custom /home/user/Downloads

# Scan multiple paths
tpj scan --scan-type custom /tmp /var/tmp /home/user/Documents

# Scan a single file
tpj scan --scan-type custom /path/to/suspicious-file.exe
```

Custom scans are ideal for:

- Checking files before opening them
- Scanning external USB drives
- Verifying a specific directory after a suspicious event

### Rootkit Scan

```bash
# Standard rootkit scan
tpj rootkit-scan

# Deep rootkit scan (slower, more thorough)
tpj rootkit-scan --deep
```

The rootkit scanner checks for:

| Check | Description |
|---|---|
| Hidden processes | Compares kernel process list with user-space enumeration to find discrepancies |
| Hidden files | Cross-view verification of filesystem entries against raw disk reads |
| Kernel module integrity | Validates loaded kernel modules against known-good signatures |
| SSDT/IDT hooks | Detects System Service Descriptor Table and Interrupt Descriptor Table modifications (Windows) |
| Syscall table hooks | Detects modified system call handlers (Linux) |
| DKOM detection | Identifies Direct Kernel Object Manipulation techniques |
| MBR/VBR integrity | Verifies Master Boot Record and Volume Boot Record against expected values |
| Driver verification | Checks all loaded drivers against signing requirements |

The `--deep` flag enables additional checks that require more time:

- Full memory forensics scan
- Cross-referencing all open file handles with visible filesystem entries
- Low-level disk read comparison for all system binaries

**Note:** Rootkit scanning requires administrator/root privileges and may temporarily increase system resource usage.

### Memory Scan

```bash
tpj scan --scan-type memory
```

Scans the memory space of all running processes. Effective against:

- Fileless malware that executes entirely in memory
- Process injection attacks (code injected into legitimate processes)
- Reflective DLL loading
- In-memory-only payloads from exploit kits

### Boot Scan

```bash
tpj scan --scan-type boot
```

Registers a scan to run at the next system boot. On Windows, this uses the Early Launch Anti-Malware (ELAM) driver to scan before other drivers and startup programs load. On Linux, it runs as an early systemd service.

Boot scans can access files that are normally locked by the OS, including:

- System registry hives (Windows)
- Locked system DLLs and executables
- MBR and VBR sectors
- Pagefile and hibernation file

---

## Real-Time (On-Access) Scanning

Real-time protection monitors file operations as they happen and scans files before they are opened, executed, or written.

### How It Works

1. The filesystem minifilter driver (Windows), fanotify/inotify (Linux), or Endpoint Security framework (macOS) intercepts file operations.
2. Before the operation completes, the file is checked against the signature database and heuristic rules.
3. If a threat is detected, the operation is blocked and the file is quarantined.
4. The user is notified through the system tray/menu bar and the event log.

### Configuration

```bash
# Enable/disable real-time scanning
tpj config --set scanner.realtime_enabled --value true

# Scan on file access (read)
tpj config --set scanner.scan_on_access --value true

# Scan on file write
tpj config --set scanner.scan_on_write --value true
```

### Performance Impact

Real-time scanning is optimized for minimal overhead:

- **Hash cache** - Files that have not changed since the last scan are skipped.
- **Extension filtering** - Only files with executable or document extensions are scanned on access by default.
- **Async scanning** - Write operations are checked asynchronously where possible to avoid blocking the calling application.

---

## Detection Engines

Every scan uses multiple detection layers in sequence:

```
File --> [Signature Match] --> [Heuristic Analysis] --> [YARA Rules] --> [Behavioral Check] --> [Sandbox] --> [JagAI]
```

| Engine | Description | Speed | Accuracy |
|---|---|---|---|
| **Signature** | SHA-256 hash lookup and byte-pattern matching using Aho-Corasick | Very fast | High (known threats only) |
| **Heuristic** | Static analysis of API imports, entropy, packing, and suspicious patterns | Fast | Moderate (may produce false positives) |
| **YARA** | Flexible rule-based pattern matching using community and custom YARA rules | Fast | High |
| **Behavioral** | Runtime monitoring of process API calls, file operations, and registry changes | Moderate | High |
| **Sandbox** | Isolated execution environment for dynamic analysis | Slow (30-60s per file) | Very high |
| **JagAI** | AI-powered analysis using the JagAI backend (subscription required) | Moderate (2-10s) | Very high |

For on-demand scans, all available engines run in sequence. For real-time scanning, only signature, heuristic, and YARA engines run synchronously; behavioral, sandbox, and AI checks are deferred to background processing for suspicious files.

---

## Interpreting Scan Results

### CLI Text Output

```
Scan completed (ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890)
---
Files scanned:  12,847
Files clean:    12,845
Files skipped:  0
Threats found:  2
Duration:       14.3s

--- Threats ---
  1. [Critical] Trojan.GenericKD.48291537 - /tmp/suspicious.exe (quarantined)
  2. [High] Rootkit.ZeroAccess.C - /var/tmp/.hidden (quarantined)

Run 'tpj quarantine list' to see quarantined items.
```

### JSON Output

For scripting and integration, use `--format json`:

```bash
tpj scan --scan-type quick --format json
```

```json
{
  "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "scan_type": "quick",
  "files_scanned": 12847,
  "files_clean": 12845,
  "files_skipped": 0,
  "threats_found": 2,
  "duration_ms": 14300,
  "threats": [
    {
      "name": "Trojan.GenericKD.48291537",
      "level": "Critical",
      "category": "trojan",
      "file_path": "/tmp/suspicious.exe",
      "hash_sha256": "a3f5b8c1d4e9f2a6b7c8d0e1f3a5b9c2...",
      "detection_method": "Signature",
      "action": "quarantined"
    }
  ]
}
```

### Result Fields Explained

| Field | Description |
|---|---|
| `files_scanned` | Total number of files examined |
| `files_clean` | Files that passed all detection checks |
| `files_skipped` | Files that were not scanned (too large, excluded, inaccessible) |
| `threats_found` | Number of files identified as threats |
| `duration_ms` | Total scan time in milliseconds |

### Threat Categories

| Category | Examples |
|---|---|
| `trojan` | Remote access trojans, banking trojans, info-stealers |
| `ransomware` | File-encrypting malware, screen lockers |
| `worm` | Self-propagating malware |
| `rootkit` | Kernel-level persistent threats |
| `backdoor` | Unauthorized remote access tools |
| `adware` | Advertising-injection software |
| `spyware` | Keyloggers, screen capture, data exfiltration |
| `miner` | Cryptocurrency mining malware |
| `exploit` | Shellcode, exploit kits, vulnerability exploitation |
| `pup` | Potentially unwanted programs |

---

## Scan Exclusions

You can exclude specific paths, file types, or processes from scanning. Exclusions apply to both on-demand and real-time scans.

```bash
# Add a path exclusion
tpj config --set scanner.exclusions --value "/home/user/VMs,/opt/build-cache"
```

In the configuration file (`config.toml`):

```toml
[scanner]
exclusions = [
    "/home/user/VMs",
    "/opt/build-cache",
    "*.iso",
    "*.vmdk",
]
```

**Warning:** Be cautious with exclusions. Excluding paths that malware commonly targets weakens your protection. Never exclude system directories like `C:\Windows\System32` or `/usr/bin`.

---

## Scheduled Scans

Schedule automatic scans using the configuration file or the web console:

```toml
[scanner.schedule]
# Quick scan every day at 2:00 AM
quick_scan_cron = "0 2 * * *"

# Full scan every Sunday at 3:00 AM
full_scan_cron = "0 3 * * 0"

# Rootkit scan every Wednesday at 4:00 AM
rootkit_scan_cron = "0 4 * * 3"
```

The daemon uses standard cron syntax for scheduling. Scheduled scans run in the background and results are logged in the event feed.

---

## Performance Tuning

### I/O Priority

By default, on-demand scans run at low I/O priority to avoid impacting other applications. Full scans use idle I/O scheduling where available.

### CPU Throttling

```toml
[scanner]
# Maximum CPU cores to use for scanning (0 = use all available)
max_scan_threads = 0

# Throttle scan speed when the system is under load
adaptive_throttling = true
```

### Scan Speed vs. Thoroughness

For faster scans that trade some thoroughness, reduce archive scanning depth:

```toml
[scanner]
max_archive_depth = 2      # Default: 5
max_file_size_mb = 256     # Default: 512
scan_archives = true
```

---

## Scanning Archives and Compressed Files

True Protection scans inside compressed and archive files, including:

| Format | Support |
|---|---|
| ZIP | Full support, including encrypted (with password prompt) |
| RAR | Full support (RAR4 and RAR5) |
| 7z | Full support |
| tar.gz / tar.bz2 / tar.xz | Full support |
| ISO | Mounted and scanned |
| CAB | Full support |
| MSI | Scanned as CAB archive |

### Archive Depth

Archives can contain other archives (e.g., a ZIP inside a ZIP). The `max_archive_depth` setting controls how many levels deep the scanner will go. The default is 5 levels.

```bash
# Check current setting
tpj config --get scanner.max_archive_depth

# Increase depth
tpj config --set scanner.max_archive_depth --value 10
```

---

## EICAR Test File

The EICAR test file is a standardized test string recognized by all antivirus products. Use it to verify that your scanner is working:

```bash
# Create an EICAR test file
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt

# Scan it
tpj scan --scan-type custom /tmp/eicar.txt
```

Expected result:

```
Threats found: 1
--- Threats ---
  1. [Info] EICAR.TestFile.Standard - /tmp/eicar.txt (quarantined)
```

The EICAR file is detected with severity "info" because it is a test file, not actual malware. If the EICAR file is not detected, check that the daemon is running and signatures are loaded.
