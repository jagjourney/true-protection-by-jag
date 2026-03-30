# JagAI Module Guide

The JagAI module is True Protection's AI-powered threat analysis layer. It provides automated threat classification, incident response assistance, proactive threat hunting, and intelligent security reporting. JagAI is a subscription feature that enhances the open-source core engine with cutting-edge AI capabilities.

---

## Table of Contents

- [What Is JagAI?](#what-is-jagai)
- [Subscription Tiers](#subscription-tiers)
- [Setting Up JagAI](#setting-up-jagai)
- [AI Scan](#ai-scan)
- [Threat Hunting](#threat-hunting)
- [Security Reports](#security-reports)
- [How AI Scanning Works](#how-ai-scanning-works)
  - [Analysis Pipeline](#analysis-pipeline)
  - [Data Anonymization](#data-anonymization)
  - [Confidence Scoring](#confidence-scoring)
  - [Caching](#caching)
- [Analysis Types](#analysis-types)
- [Rate Limits and Quotas](#rate-limits-and-quotas)
- [Privacy and Data Handling](#privacy-and-data-handling)
- [CLI Commands](#cli-commands)
- [Configuration Reference](#configuration-reference)
- [FAQ](#faq)

---

## What Is JagAI?

JagAI is an AI-powered cybersecurity analyst integrated directly into the True Protection scanner pipeline. When the conventional engines (signature, heuristic, YARA, behavioral) flag a file as suspicious but cannot make a definitive determination, JagAI steps in to provide deep analysis.

JagAI can:

- **Classify unknown threats** with confidence scoring and severity assessment
- **Extract indicators of compromise (IOCs)** such as C2 domains, suspicious IPs, and malicious hashes
- **Map threats to MITRE ATT&CK techniques** for standardized threat intelligence
- **Generate human-readable reports** explaining what a threat does and how to remediate it
- **Hunt for threats proactively** using natural-language queries across your endpoint data
- **Correlate anomalies** across multiple events to detect multi-stage attack campaigns

**Important:** JagAI enhances but does not replace the core detection engines. The core engine operates fully offline and does not depend on the AI module. Files are never uploaded to the cloud - only anonymized metadata is sent for analysis.

---

## Subscription Tiers

| Tier | Price | AI Scans/Day | Features |
|---|---|---|---|
| **Free** | $0 | 0 | Full open-source engine, community signatures, firewall, AV, anti-rootkit, HIPS, NIDS, CLI, desktop GUI. No AI features. |
| **Personal** | $4.99/mo | 50 | AI threat scanning, basic AI-generated reports, email alerts |
| **Professional** | $14.99/mo | 1,000 | Full AI feature set, advanced threat hunting, priority signature updates, API access |
| **Enterprise** | $49.99/seat/mo | 50,000 | Central management, fleet-wide AI threat hunting, compliance reporting, SIEM integration, dedicated support, custom rule authoring |

Annual billing is available at a 20% discount. All paid tiers include a 14-day free trial.

### Per-Tier Rate Limits

| Tier | Requests/Minute | Requests/Day | Max Tokens/Request |
|---|---|---|---|
| Personal | 5 | 50 | 2,048 |
| Professional | 30 | 1,000 | 4,096 |
| Enterprise | 120 | 50,000 | 8,192 |

---

## Setting Up JagAI

### 1. Subscribe

Visit [https://trueprotection.dev/pricing](https://trueprotection.dev/pricing) and choose a plan. After payment, you will receive an API key.

### 2. Configure the API Key

```bash
# Set the API key (stored encrypted on disk)
tpj config --set ai.api_key --value "tpj_key_xxxxxxxxxxxxxxxxxxxx"

# Enable the module
tpj config --set ai.enabled --value true
```

### 3. Verify

```bash
tpj ai status
```

Expected output:

```
JagAI Module: active
Tier:         Professional
Scans today:  0 / 1,000
Rate limit:   0 / 30 per minute
API endpoint: https://api.trueprotection.dev/v1
```

---

## AI Scan

Submit a specific file for deep AI analysis:

```bash
tpj ai scan /path/to/suspicious-file.exe
```

The AI scan extracts metadata from the file (hash, size, type, entropy, import table, string artifacts, behavioral indicators) and sends the anonymized data to JagAI for classification.

Example output:

```
JagAI Analysis Report
---
File:           /path/to/suspicious-file.exe
SHA-256:        a3f5b8c1d4e9f2a6b7c8d0e1f3a5b9c2...
File Type:      PE32 executable (GUI) Intel 80386

Verdict:        MALICIOUS
Confidence:     0.94 (very high)
Severity:       Critical

Capabilities:
  - Keylogging
  - Data exfiltration
  - Registry persistence

MITRE ATT&CK:
  - T1056.001 (Input Capture: Keylogging)
  - T1041 (Exfiltration Over C2 Channel)
  - T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys)

IOCs:
  - C2: 185.234.xxx.xxx:443
  - Domain: update-service[.]malicious[.]example

Recommended Action: Quarantine

Reasoning:
  AI verdict: 'malicious' with very high confidence (raw=0.94,
  calibrated=0.93). Severity: Critical. Recommended action: Block.
```

---

## Threat Hunting

Use natural-language queries to search across your endpoint for specific threats or suspicious patterns:

```bash
# Hunt for signs of lateral movement
tpj ai hunt "Find processes that opened remote SMB shares in the last 24 hours"

# Look for persistence mechanisms
tpj ai hunt "Show all new entries in startup locations created this week"

# Search for data exfiltration
tpj ai hunt "Identify processes that sent more than 100MB of outbound data today"
```

JagAI translates your natural-language query into structured searches across the endpoint telemetry and returns results with context.

---

## Security Reports

Generate AI-powered security reports:

```bash
# Daily summary
tpj ai report --report-type daily

# Weekly summary
tpj ai report --report-type weekly

# Full security posture assessment
tpj ai report --report-type full
```

Reports include:

- Threat summary (detected, blocked, quarantined)
- Most common threat categories
- Firewall activity highlights
- Signature update status
- Recommendations for improving security posture
- MITRE ATT&CK heat map of detected techniques

---

## How AI Scanning Works

### Analysis Pipeline

When a file is submitted for AI analysis, it goes through a multi-stage pipeline:

```
File Metadata Extraction
        |
        v
  Data Anonymization (strip PII, paths, hostnames, internal IPs)
        |
        v
  Cache Check (skip API call if identical analysis exists)
        |
        v
  JagAI API Request (send anonymized metadata)
        |
        v
  Response Parsing (extract structured JSON from AI response)
        |
        v
  Confidence Scoring (calibrate raw score, determine severity)
        |
        v
  Action Recommendation (block, quarantine, alert, log, or manual review)
        |
        v
  Result Caching (store for future lookups)
```

### Data Anonymization

Before any data leaves your machine, the anonymizer strips:

| Data Type | Redaction |
|---|---|
| Windows user paths (`C:\Users\JohnDoe\...`) | Replaced with `C:\Users\[REDACTED]\...` |
| Linux/macOS home paths | Replaced with `/home/[REDACTED]/...` |
| Hostnames | Replaced with `[REDACTED-HOST]` |
| Usernames | Replaced with `[REDACTED-USER]` |
| Private IP addresses (RFC 1918) | Replaced with `[REDACTED-IP]` |
| Email addresses | Replaced with `[REDACTED-EMAIL]` |
| Windows SIDs | Replaced with `[REDACTED-SID]` |

Public IP addresses, file hashes, and non-PII metadata are preserved because they are essential for accurate threat classification.

### Confidence Scoring

The raw AI confidence score (0.0 to 1.0) is calibrated using multiple factors:

1. **Severity alignment** - If the AI reports "critical" severity but low confidence, the score is penalized for inconsistency.
2. **Verdict weighting** - Clean verdicts with high confidence are boosted. Threat verdicts are blended with severity weight.
3. **Action mapping** based on calibrated confidence:

| Calibrated Confidence | Threat Verdict | Severity | Action |
|---|---|---|---|
| >= 0.85 | Yes | Critical | **Block** |
| >= 0.85 | Yes | High | **Quarantine** |
| >= 0.85 | Yes | Medium | **Alert** |
| 0.50 - 0.85 | Yes | Critical/High | **Quarantine** |
| 0.50 - 0.85 | Yes | Medium/Low | **Alert** |
| 0.30 - 0.50 | Yes | Any | **Log Only** |
| < 0.30 | Yes | Any | **Manual Review** |
| >= 0.50 | No | Any | **No Action** |
| < 0.50 | No | Any | **Manual Review** |

### Caching

Analysis results are cached locally to avoid redundant API calls. If the same file (by hash) has been analyzed recently, the cached result is returned instantly.

- Cache TTL: 24 hours by default
- Maximum cache size: 10,000 entries
- Cache is stored on disk in the data directory

---

## Analysis Types

JagAI supports five analysis types, each with a specialized prompt template:

| Type | Template | Use Case |
|---|---|---|
| **Malware Analysis** | `malware_analysis.txt` | Deep analysis of suspicious executables and documents |
| **Network Analysis** | `network_analysis.txt` | Classify suspicious network traffic patterns |
| **Incident Response** | `incident_response.txt` | Guided remediation after a confirmed incident |
| **Threat Hunting** | `threat_hunting.txt` | Proactive search for hidden threats |
| **Security Report** | `security_report.txt` | Generate summary reports of security posture |

---

## Rate Limits and Quotas

Rate limits are enforced locally before any API call is made:

- **Per-minute limit** - Sliding window; if exceeded, requests are delayed until the window resets.
- **Per-day limit** - Hard limit that resets at midnight UTC. When exhausted, AI features are unavailable until the next day.

Check your current usage:

```bash
tpj ai status
```

If you consistently hit rate limits, consider upgrading your subscription tier.

---

## Privacy and Data Handling

True Protection is designed with privacy as a core principle:

1. **No file uploads.** Files are never sent to the cloud. Only extracted, anonymized metadata is transmitted.
2. **PII stripping.** All personally identifiable information is removed before transmission.
3. **Local-first.** The core engine works entirely offline. JagAI is optional.
4. **Encrypted transport.** All API communication uses TLS 1.3.
5. **No telemetry.** True Protection does not collect or transmit usage telemetry, analytics, or behavioral data unless explicitly opted in.

---

## CLI Commands

| Command | Description |
|---|---|
| `tpj ai scan <path>` | Submit a file for AI analysis |
| `tpj ai hunt "<query>"` | Run an AI-powered threat hunt |
| `tpj ai report --report-type <type>` | Generate a security report (daily, weekly, full) |
| `tpj ai status` | Check subscription status, tier, and usage |

---

## Configuration Reference

```toml
[ai]
# Enable/disable the JagAI module
enabled = false

# JagAI API endpoint
api_endpoint = "https://api.trueprotection.dev/v1"

# Subscription tier (set automatically from API key)
subscription_tier = "Professional"

# Maximum daily scans (set automatically from tier)
max_daily_scans = 1000

# Anonymize data before sending (strongly recommended)
anonymize_data = true

# Cache analysis results
enable_cache = true

# Cache TTL in seconds (default: 86400 = 24 hours)
cache_ttl_seconds = 86400

# Maximum cached entries
cache_max_entries = 10000
```

---

## FAQ

**Q: Does JagAI upload my files to the cloud?**
A: No. Only anonymized metadata (file hash, size, type, entropy, import table summary, and behavioral indicators) is sent. The file itself never leaves your machine.

**Q: What happens when my daily quota runs out?**
A: The core engine continues to protect you using signature, heuristic, YARA, and behavioral detection. Only the AI-powered analysis becomes unavailable until the quota resets at midnight UTC.

**Q: Can I use JagAI offline?**
A: No. JagAI requires an internet connection to communicate with the JagAI backend API. The core engine works fully offline.

**Q: What AI model does JagAI use?**
A: JagAI is powered by a state-of-the-art large language model fine-tuned for cybersecurity analysis. The specific model may change as newer, more capable models become available.

**Q: Can I bring my own API key?**
A: Enterprise tier customers can configure custom API endpoints. Contact support for details.
