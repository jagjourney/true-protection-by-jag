# Firewall Configuration

True Protection by Jag includes a stateful, application-aware firewall with deep packet inspection (DPI) capabilities. It uses platform-native backends - WFP on Windows, eBPF/nftables on Linux, and Network Extension on macOS - to deliver wire-speed traffic analysis with minimal overhead.

---

## Table of Contents

- [Overview](#overview)
- [Enabling and Disabling the Firewall](#enabling-and-disabling-the-firewall)
- [Default Policies](#default-policies)
- [Managing Rules](#managing-rules)
  - [Listing Rules](#listing-rules)
  - [Adding Rules](#adding-rules)
  - [Deleting Rules](#deleting-rules)
  - [Rule Priority and Ordering](#rule-priority-and-ordering)
- [Application Control](#application-control)
- [Geo-Blocking](#geo-blocking)
- [Stealth Mode](#stealth-mode)
- [Deep Packet Inspection](#deep-packet-inspection)
- [IDS/IPS Integration](#idsips-integration)
- [Firewall Profiles](#firewall-profiles)
- [Logging and Monitoring](#logging-and-monitoring)
- [Configuration Reference](#configuration-reference)
- [Troubleshooting](#troubleshooting)

---

## Overview

The firewall operates at two levels:

1. **Packet filtering** - Stateful inspection of network packets using allow/block rules based on IP addresses, ports, protocols, and direction.
2. **Application control** - Rules bound to specific executables, so you can allow `firefox.exe` to access port 443 while blocking `unknown-app.exe` from any network access.

All traffic decisions are logged and reported through the event system, appearing in the dashboard and CLI logs.

---

## Enabling and Disabling the Firewall

```bash
# Check current firewall status
tpj status

# Enable the firewall
tpj firewall toggle on

# Disable the firewall
tpj firewall toggle off
```

Or via the configuration file:

```toml
[firewall]
enabled = true
```

**Warning:** Disabling the firewall removes all network filtering. Your system will rely solely on OS-level firewall rules (if any). Only disable the True Protection firewall for troubleshooting.

---

## Default Policies

Default policies apply to traffic that does not match any explicit rule.

| Policy | Default | Description |
|---|---|---|
| **Inbound** | `Block` | All unsolicited inbound connections are blocked unless a rule explicitly allows them |
| **Outbound** | `Allow` | Outbound connections are permitted by default unless a rule blocks them |

### Changing Default Policies

```bash
# Block all outbound by default (strict mode)
tpj config --set firewall.default_outbound --value Block

# Allow all inbound (not recommended)
tpj config --set firewall.default_inbound --value Allow

# Prompt for unknown connections
tpj config --set firewall.default_outbound --value Prompt
```

In `config.toml`:

```toml
[firewall]
enabled = true
default_inbound = "Block"
default_outbound = "Allow"
```

The three possible policy values are:

| Policy | Behavior |
|---|---|
| `Allow` | Traffic is permitted unless a block rule matches |
| `Block` | Traffic is denied unless an allow rule matches |
| `Prompt` | The GUI prompts the user to allow or block each new connection (desktop only) |

---

## Managing Rules

### Listing Rules

```bash
# List all active firewall rules
tpj firewall list
```

Example output:

```
ID          Name                  Action  Direction  Protocol  Port   Application
----------  --------------------  ------  ---------  --------  -----  -----------------
fw-001      Allow HTTP            allow   outbound   tcp       80     *
fw-002      Allow HTTPS           allow   outbound   tcp       443    *
fw-003      Allow DNS             allow   outbound   udp       53     *
fw-004      Block Telnet          block   both       tcp       23     *
fw-005      Firefox Web           allow   outbound   tcp       *      /usr/bin/firefox
fw-006      SSH Server            allow   inbound    tcp       22     /usr/sbin/sshd
```

### Adding Rules

```bash
# Allow HTTPS traffic for all applications
tpj firewall add \
  --name "Allow HTTPS" \
  --action allow \
  --direction outbound \
  --protocol tcp \
  --port 443

# Block a specific application from network access
tpj firewall add \
  --name "Block Suspicious App" \
  --action block \
  --direction both \
  --protocol any \
  --app "/path/to/suspicious-app"

# Allow inbound SSH
tpj firewall add \
  --name "SSH Access" \
  --action allow \
  --direction inbound \
  --protocol tcp \
  --port 22
```

#### Rule Parameters

| Parameter | Values | Default | Description |
|---|---|---|---|
| `--name` | Any string | Required | Human-readable rule name |
| `--action` | `allow`, `block` | Required | Whether to permit or deny matching traffic |
| `--direction` | `inbound`, `outbound`, `both` | `both` | Direction of traffic the rule applies to |
| `--protocol` | `tcp`, `udp`, `any` | `any` | Network protocol to match |
| `--port` | 1-65535 | None (all ports) | Destination port number |
| `--app` | File path | None (all apps) | Path to the application executable |

### Deleting Rules

```bash
# Delete a rule by ID
tpj firewall delete fw-004
```

### Rule Priority and Ordering

Rules are evaluated in order from most specific to least specific:

1. Rules with both application and port specified
2. Rules with application specified (any port)
3. Rules with port specified (any application)
4. Rules with only protocol and direction
5. Default policy

Within the same specificity level, **block rules take precedence over allow rules**. If a connection matches both an allow and a block rule at the same level, it is blocked.

---

## Application Control

Application control binds firewall rules to specific executables. This prevents unauthorized programs from accessing the network, even if general rules would allow the traffic.

### How It Works

1. When an application attempts a network connection, the firewall identifies the process and its executable path.
2. The process signature is verified against the expected hash (if configured).
3. Rules matching that application are evaluated.
4. If no application-specific rule matches, the general rules and default policy apply.

### Creating Application Rules

```bash
# Allow only Firefox to access the web
tpj firewall add --name "Firefox HTTP" --action allow --direction outbound --protocol tcp --port 80 --app "/usr/bin/firefox"
tpj firewall add --name "Firefox HTTPS" --action allow --direction outbound --protocol tcp --port 443 --app "/usr/bin/firefox"

# Block a specific application entirely
tpj firewall add --name "Block Crypto Miner" --action block --direction both --protocol any --app "/tmp/xmrig"
```

### Application Learning Mode

When the firewall is in learning mode, it observes which applications make network connections and automatically creates allow rules for known-good applications.

```toml
[firewall]
learning_mode = true
learning_duration_hours = 24
```

After the learning period, review the generated rules and switch to enforcement mode.

---

## Geo-Blocking

Geo-blocking restricts network connections based on the geographic location of the remote IP address, using a regularly updated GeoIP database.

### Enabling Geo-Blocking

```bash
# Enable geo-blocking
tpj config --set firewall.geo_blocking_enabled --value true

# Block traffic from specific countries (ISO 3166-1 alpha-2 codes)
tpj config --set firewall.blocked_countries --value "CN,RU,KP,IR"
```

In `config.toml`:

```toml
[firewall]
geo_blocking_enabled = true
blocked_countries = ["CN", "RU", "KP", "IR"]
```

### GeoIP Database Updates

The GeoIP database is updated automatically alongside signature updates. You can also trigger a manual update:

```bash
tpj update
```

### Geo-Blocking Caveats

- Geo-blocking operates on IP addresses, not domain names. A CDN-hosted website may have servers in multiple countries.
- VPN and proxy traffic may originate from a different country than the actual source.
- Geo-blocking is applied to both inbound and outbound connections.
- Blocked connections are logged with the matched country code.

---

## Stealth Mode

Stealth mode makes your system invisible to port scanners and network reconnaissance tools.

```bash
tpj config --set firewall.stealth_mode --value true
```

When stealth mode is enabled:

- Unsolicited inbound packets are dropped silently (no ICMP destination-unreachable or TCP RST responses).
- Ping (ICMP echo) requests are ignored.
- Port scans receive no response, making it appear as if no host exists at your IP address.

**Note:** Stealth mode may interfere with some network diagnostic tools and legitimate services that rely on ICMP responses.

---

## Deep Packet Inspection

The DPI engine analyzes the content of network connections beyond just headers. It can detect:

| Protocol | Analysis Capability |
|---|---|
| HTTP/HTTPS | URL filtering, malicious payload detection, C2 communication patterns |
| DNS | Malicious domain detection, DNS tunneling, DGA domain identification |
| SMB | Lateral movement detection, suspicious share access patterns |
| SSH | Brute-force detection, unusual key exchange patterns |
| SMTP/IMAP | Malicious attachment detection, phishing link identification |
| FTP | Suspicious file transfer patterns, data exfiltration indicators |

For encrypted traffic (HTTPS, SSH), the DPI engine uses metadata analysis (JA3/JA4 fingerprinting, certificate validation, SNI inspection) rather than content inspection, preserving privacy while detecting threats.

---

## IDS/IPS Integration

The firewall includes built-in Intrusion Detection System (IDS) and Intrusion Prevention System (IPS) capabilities.

| Mode | Behavior |
|---|---|
| **IDS** (detection only) | Logs alerts for suspicious traffic but does not block it |
| **IPS** (prevention) | Blocks traffic that matches intrusion signatures in real time |

```toml
[firewall.ids]
enabled = true
mode = "ips"  # "ids" or "ips"
```

IDS/IPS alerts appear in the event feed alongside regular firewall logs.

---

## Firewall Profiles

Profiles allow you to switch between different rule sets based on your environment.

| Profile | Description |
|---|---|
| **Home** | Relaxed rules for trusted home networks |
| **Public** | Strict rules for untrusted networks (cafes, airports) |
| **Enterprise** | Managed rules pushed from the central management server |
| **Custom** | User-defined rule sets |

```bash
# Switch to the Public profile
tpj config --set firewall.active_profile --value public
```

---

## Logging and Monitoring

### Viewing Firewall Logs

```bash
# Show recent firewall events
tpj log --component firewall --lines 20

# Export firewall logs
tpj log --component firewall --export /tmp/firewall-log.json
```

### Log Verbosity

```toml
[firewall]
log_blocked = true    # Log all blocked connections (default: true)
log_allowed = false   # Log allowed connections (default: false, produces high volume)
```

---

## Configuration Reference

Complete `config.toml` section for the firewall:

```toml
[firewall]
# Master enable/disable
enabled = true

# Default policies
default_inbound = "Block"     # Block, Allow, or Prompt
default_outbound = "Allow"    # Block, Allow, or Prompt

# Stealth mode (drop unsolicited packets silently)
stealth_mode = false

# Logging
log_blocked = true
log_allowed = false

# Geo-blocking
geo_blocking_enabled = false
blocked_countries = []

# Application control
learning_mode = false
learning_duration_hours = 24

# Active profile
active_profile = "home"

# IDS/IPS
[firewall.ids]
enabled = true
mode = "ips"
```

---

## Troubleshooting

### "Firewall: error" in Status Output

This usually means the kernel driver failed to load. Common causes:

- **Windows:** WFP callout driver not signed or not installed. Run the installer again as Administrator.
- **Linux:** The eBPF program failed to load (kernel version too old, or `libbpf` not installed). Minimum kernel version: 5.10.
- **macOS:** The Network Extension was not approved. Go to **System Settings > Privacy & Security** and approve the extension.

### Certain Applications Cannot Connect

1. Check if an explicit block rule exists: `tpj firewall list`
2. Check if the default outbound policy is set to `Block`
3. Check if geo-blocking is blocking the destination country
4. View the firewall log for blocked events: `tpj log --component firewall --lines 50`

### Geo-Blocking Not Working

Verify that the GeoIP database is loaded:

```bash
tpj diagnose
```

Look for the "GeoIP database" line. If it shows "not loaded", run `tpj update` to download the latest database.
