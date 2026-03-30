# Understanding the Dashboard and Protection Status

True Protection by Jag provides a real-time view of your system's security posture through the desktop GUI, web console, and CLI status output. This guide explains every indicator, what the protection states mean, and how to interpret the information presented.

---

## Table of Contents

- [Checking Status via CLI](#checking-status-via-cli)
- [Protection Status Overview](#protection-status-overview)
- [Component Status Indicators](#component-status-indicators)
- [The Desktop Dashboard (Qt GUI)](#the-desktop-dashboard-qt-gui)
- [The Web Console](#the-web-console)
- [Event Feed and Notifications](#event-feed-and-notifications)
- [Understanding Threat Levels](#understanding-threat-levels)
- [System Tray / Menu Bar Icon](#system-tray--menu-bar-icon)

---

## Checking Status via CLI

The quickest way to check your protection status is:

```bash
tpj status
```

Example output:

```
True Protection by Jag v0.1.0
---
Status:     Active
Firewall:   enabled
Scanner:    ready
Real-time:  enabled
HIPS:       enabled
Signatures: v2026.03.27 (142,587 signatures)
AI Module:  active (Professional)
Uptime:     14h 32m 8s
```

For machine-readable output:

```bash
tpj status --format json
```

```json
{
  "version": "0.1.0",
  "protection_status": "active",
  "firewall": "enabled",
  "scanner": "ready",
  "realtime": "enabled",
  "hips": "enabled",
  "signatures": "v2026.03.27",
  "signatures_count": 142587,
  "ai_module": "active",
  "ai_tier": "Professional",
  "uptime_seconds": 52328
}
```

---

## Protection Status Overview

The top-level protection status reflects the aggregate health of all security components. There are four possible states:

| Status | Meaning | Action Required |
|---|---|---|
| **Active** | All protection modules are running and up to date. Your system is fully protected. | None. |
| **Degraded** | One or more modules have issues but core protection is still functioning. | Check which component is degraded using `tpj status` or `tpj diagnose`. |
| **Disabled** | Protection has been manually disabled by the user or administrator. | Re-enable protection if this was not intentional. |
| **Busy** | The engine is performing a long-running operation such as a full scan or a major update. | Wait for the operation to complete. Protection remains active during this state. |

### What Causes "Degraded" Status?

The status drops to Degraded when any of these conditions exist:

- The firewall is disabled or encountered a driver error
- Real-time scanning is turned off
- Signature database is more than 48 hours out of date
- HIPS module failed to initialize
- A kernel driver is unsigned or failed to load
- The daemon lost connection to a required system component

Run `tpj diagnose` for a detailed breakdown of any issues.

---

## Component Status Indicators

Each protection component reports its own status independently.

### Firewall

| Status | Description |
|---|---|
| `enabled` | Firewall is active and filtering traffic according to rules |
| `disabled` | Firewall is turned off; no network filtering is active |
| `error` | Firewall encountered an error (driver not loaded, permission issue) |
| `learning` | Firewall is in learning mode, building application profiles |

### Scanner

| Status | Description |
|---|---|
| `ready` | Scanner is idle and ready to process scan requests |
| `scanning` | A scan is currently in progress |
| `updating` | Signature database is being updated |
| `error` | Scanner failed to initialize (signature database missing or corrupt) |

### Real-Time Protection

| Status | Description |
|---|---|
| `enabled` | File access and write events are being monitored in real time |
| `disabled` | Real-time monitoring is turned off |
| `paused` | Temporarily paused (e.g., during a full system scan to reduce I/O) |

### HIPS (Host Intrusion Prevention System)

| Status | Description |
|---|---|
| `enabled` | Process integrity monitoring, registry guards, and exploit mitigation are active |
| `disabled` | HIPS is turned off |
| `partial` | Some HIPS features are active but others failed to initialize |

### Signatures

The signatures line shows the database version and total number of loaded signatures. Example:

```
Signatures: v2026.03.27 (142,587 signatures)
```

If signatures are out of date, you will see a warning:

```
Signatures: v2026.03.20 (140,012 signatures) [OUTDATED - 7 days old]
```

Run `tpj update` to refresh signatures immediately.

### AI Module

| Status | Description |
|---|---|
| `active (Tier)` | JagAI is enabled and connected. The tier name (Personal, Professional, Enterprise) is shown. |
| `not configured` | No API key has been set. The AI module is not available. |
| `inactive` | Subscription has expired or been cancelled. |
| `quota exceeded` | Daily scan quota has been reached. Resets at midnight UTC. |
| `error` | Cannot reach the JagAI API. Check network connectivity. |

---

## The Desktop Dashboard (Qt GUI)

The desktop application (available on Windows and Linux) provides a graphical dashboard with the following panels:

### Protection Shield

A large shield icon in the center of the dashboard. Its color indicates the overall status:

- **Green shield** - Active. Full protection.
- **Yellow shield** - Degraded. One or more components need attention.
- **Red shield** - Disabled or critical error. Immediate attention required.
- **Blue shield** - Busy. A scan or update is in progress.

### Component Cards

Below the shield, each component (Firewall, Scanner, Real-Time, HIPS, AI Module) has a card showing:

- Component name and status
- Last activity timestamp
- Quick-action button (enable/disable, run scan, etc.)

### Threat Timeline

A chronological feed of recent events:

- Threats detected and actions taken
- Firewall blocks
- Signature updates
- Status changes

### Statistics Panel

- Files scanned in the last 24 hours
- Threats blocked in the last 7 days
- Network connections blocked today
- AI analyses performed (if subscribed)

---

## The Web Console

For Linux servers and headless deployments, the web console provides the same dashboard in a browser at `http://localhost:9876` (default).

Access the web console:

```bash
# The web console starts with the daemon on Linux Server installations
# Default: http://localhost:9876

# To change the bind address (for remote access):
tpj config --set web_console.bind --value "0.0.0.0:9876"
```

**Security note:** If you expose the web console beyond localhost, always use a reverse proxy with TLS and authentication. The web console uses token-based authentication for remote access.

---

## Event Feed and Notifications

True Protection publishes events on an internal event bus. These events appear in the dashboard event feed and can trigger system notifications.

### Event Types

| Event | Description |
|---|---|
| `ThreatDetected` | A threat was identified by any detection engine (signature, heuristic, behavioral, sandbox, AI, YARA, network) |
| `FileQuarantined` | A file was moved to the quarantine vault |
| `ScanCompleted` | A scan operation finished, with summary statistics |
| `ConnectionBlocked` | The firewall blocked a network connection |
| `StatusChanged` | Overall protection status changed (e.g., Active to Degraded) |
| `SignaturesUpdated` | The signature database was updated to a new version |
| `UpdateAvailable` | A new application version is available for download |
| `HealthCheck` | A component health check reported an issue |

### Viewing Events via CLI

```bash
# Show the last 50 log entries
tpj log --lines 50

# Filter by component
tpj log --component firewall

# Filter by component and export
tpj log --component scanner --export /tmp/scanner-logs.json
```

---

## Understanding Threat Levels

When threats are detected, they are assigned a severity level:

| Level | Color | Description | Typical Action |
|---|---|---|---|
| **Critical** | Red | Confirmed high-impact threat (ransomware, rootkit, active exploit) | Auto-quarantine or block |
| **High** | Orange | Likely malicious (trojans, backdoors, spyware) | Auto-quarantine |
| **Medium** | Yellow | Suspicious behavior or potentially unwanted program (PUP) | Alert user, suggest quarantine |
| **Low** | Blue | Minor risk (adware, tracking cookies, low-severity PUP) | Log only, user notification |
| **Info** | Gray | Informational finding (test files like EICAR, known-clean packers) | Log only |

### Detection Methods

Each finding also shows how it was detected:

| Method | Description |
|---|---|
| Signature | Matched a known malware hash or byte pattern in the signature database |
| Heuristic | Static code analysis identified suspicious patterns (API combinations, entropy, packing) |
| Behavioral | Runtime monitoring detected malicious process behavior |
| Sandbox | Detonation in an isolated environment revealed malicious activity |
| AI Analysis | JagAI classified the sample as malicious based on multi-factor analysis |
| YARA Rule | Matched a YARA rule (community or custom) |
| Network Signature | Network traffic matched a known malicious pattern |
| Reputation | File reputation service flagged the hash |

---

## System Tray / Menu Bar Icon

On desktop platforms, True Protection runs a system tray icon (Windows/Linux) or menu bar icon (macOS) that provides:

- **Quick status view** - Hover to see the current protection status
- **Quick scan** - Right-click > Quick Scan
- **Pause protection** - Right-click > Pause Protection (for a configurable duration)
- **Open dashboard** - Double-click to open the full GUI
- **Notifications** - Balloon/banner notifications for threats, updates, and status changes

### Tray Icon Colors

| Color | Meaning |
|---|---|
| Green | All protection active |
| Yellow | Degraded - check dashboard for details |
| Red | Protection disabled or critical error |
| Blue (animated) | Scan or update in progress |
