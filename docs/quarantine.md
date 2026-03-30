# Managing Quarantined Files

When True Protection detects a threat, the infected file is moved to an encrypted quarantine vault where it cannot execute or cause harm. This guide explains how quarantine works and how to manage quarantined items.

---

## Table of Contents

- [How Quarantine Works](#how-quarantine-works)
- [Listing Quarantined Items](#listing-quarantined-items)
- [Restoring a File](#restoring-a-file)
- [Permanently Deleting a File](#permanently-deleting-a-file)
- [Quarantine Vault Location](#quarantine-vault-location)
- [Automatic Cleanup](#automatic-cleanup)
- [Submitting False Positives](#submitting-false-positives)

---

## How Quarantine Works

When a threat is detected (by any engine - signature, heuristic, behavioral, sandbox, YARA, or JagAI), the following happens:

1. **The file is renamed and moved** to the quarantine vault directory.
2. **The file is encrypted** using AES-256 to prevent accidental execution or extraction by other programs.
3. **Original metadata is recorded**, including the original file path, SHA-256 hash, detection name, detection method, and timestamp.
4. **A `FileQuarantined` event is published** to the event bus, which triggers GUI/tray notifications and log entries.

Quarantined files cannot:

- Be executed by the operating system
- Be opened or read by any application
- Be accessed without explicitly restoring them through True Protection

---

## Listing Quarantined Items

```bash
tpj quarantine list
```

Example output:

```
ID                                    Threat Name                    Severity  Original Path                           Date
------------------------------------  -----------------------------  --------  -------------------------------------   -------------------
a1b2c3d4-e5f6-7890-abcd-ef1234567890  Trojan.GenericKD.48291537      Critical  /tmp/suspicious.exe                     2026-03-27 14:32:08
b2c3d4e5-f6a7-8901-bcde-f12345678901  Adware.BrowserAssist.E         Low       /home/user/Downloads/free-tool.exe      2026-03-27 09:15:44
c3d4e5f6-a7b8-9012-cdef-123456789012  Rootkit.ZeroAccess.C           Critical  /var/tmp/.hidden                        2026-03-26 22:47:31
```

For JSON output:

```bash
tpj quarantine list --format json
```

---

## Restoring a File

If you believe a quarantined file is a false positive, you can restore it to its original location:

```bash
tpj quarantine restore a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

**Warning:** Restoring a file removes it from quarantine and places it back at its original path. If the file is genuinely malicious, it will be able to execute again. Real-time protection will re-scan the restored file - if the detection is still valid, the file may be quarantined again immediately.

### Restoring and Excluding

If you need to restore a file and prevent it from being quarantined again (because you have verified it is safe):

1. Restore the file:
   ```bash
   tpj quarantine restore <id>
   ```

2. Add the file path to scanner exclusions:
   ```bash
   tpj config --set scanner.exclusions --value "/path/to/false-positive.exe"
   ```

**Caution:** Only add exclusions for files you have thoroughly verified as safe. Excluding files weakens your protection.

---

## Permanently Deleting a File

To permanently delete a quarantined file (it cannot be recovered):

```bash
tpj quarantine delete a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

You will be asked to confirm the deletion:

```
Are you sure you want to permanently delete:
  Trojan.GenericKD.48291537 (originally at /tmp/suspicious.exe)
This cannot be undone. [y/N]: y

File permanently deleted.
```

### Bulk Delete

To delete all quarantined items older than a certain age:

```bash
# Delete items older than 30 days
tpj quarantine delete --older-than 30d

# Delete all quarantined items
tpj quarantine delete --all
```

---

## Quarantine Vault Location

| Platform | Quarantine Directory |
|---|---|
| **Windows** | `C:\ProgramData\TrueProtection\Quarantine\` |
| **Linux** | `/var/lib/true-protection/quarantine/` |
| **macOS** | `/Library/Application Support/TrueProtection/Quarantine/` |

The quarantine directory is protected by filesystem permissions (readable only by root/SYSTEM) and the files inside are AES-256 encrypted. Do not manually modify files in this directory.

### Vault Structure

Each quarantined file has an associated metadata sidecar file:

```
quarantine/
  a1b2c3d4-e5f6-7890-abcd-ef1234567890.qvault     # Encrypted file data
  a1b2c3d4-e5f6-7890-abcd-ef1234567890.meta.json   # Metadata
```

The metadata JSON contains:

```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "original_path": "/tmp/suspicious.exe",
  "threat_name": "Trojan.GenericKD.48291537",
  "threat_level": "Critical",
  "threat_category": "trojan",
  "detection_method": "Signature",
  "hash_sha256": "a3f5b8c1d4e9f2a6b7c8d0e1f3a5b9c2...",
  "quarantined_at": "2026-03-27T14:32:08Z",
  "file_size_bytes": 45056,
  "encrypted": true
}
```

---

## Automatic Cleanup

By default, quarantined files are kept indefinitely. You can configure automatic cleanup in `config.toml`:

```toml
[quarantine]
# Automatically delete quarantined files after this many days (0 = never)
auto_delete_days = 90

# Maximum quarantine vault size in MB (0 = unlimited)
max_vault_size_mb = 5000

# When vault is full, delete oldest items first
eviction_policy = "oldest_first"
```

When `auto_delete_days` is set, a background task runs daily and permanently deletes quarantined items older than the threshold.

When the vault exceeds `max_vault_size_mb`, the oldest items are deleted until the vault is back under the limit.

---

## Submitting False Positives

If you believe a detection is a false positive, please help improve True Protection by reporting it:

1. Note the quarantine ID and threat name from `tpj quarantine list`.
2. Open an issue on the [GitHub issue tracker](https://github.com/jagjourney/true-protection-by-jag/issues) with:
   - The detection name (e.g., `Trojan.GenericKD.48291537`)
   - The SHA-256 hash of the file
   - A description of the file and its legitimate purpose
   - The detection method (Signature, Heuristic, YARA, etc.)
3. If the file is not confidential, consider uploading it to a malware analysis service (e.g., VirusTotal) and including the link.

False positive reports are reviewed by the signature team and corrections are included in the next signature update.
