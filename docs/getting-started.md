# Getting Started with True Protection by Jag

**True Protection by Jag** is a proprietary, free-to-use security suite. The current public cut is a **Windows 10/11 user-mode** install: Qt GUI, `tpj` CLI, and the `TpjDaemon` service. The firewall talks to Windows Firewall through INetFw. Kernel-level protection (WFP, minifilter, anti-rootkit driver) is not in this MSI.

This guide covers Windows install and first run. Linux DEB/RPM packages are produced by the tagged release pipeline; they are not the launch product. macOS, iOS, Android, winget, Homebrew, and AUR are not supported.

---

## Table of Contents

- [System Requirements](#system-requirements)
- [Install on Windows](#install-on-windows)
- [Verify the install](#verify-the-install)
- [First run](#first-run)
- [The daemon service](#the-daemon-service)
- [Run a scan](#run-a-scan)
- [Firewall](#firewall)
- [JagAI (optional)](#jagai-optional)
- [Uninstall](#uninstall)
- [Next Steps](#next-steps)

---

## System Requirements

| Requirement | This release |
|---|---|
| **OS** | Windows 10 or later, 64-bit |
| **CPU** | x86_64, 2 cores |
| **RAM** | 2 GB (4 GB recommended) |
| **Disk** | 500 MB free (more if quarantine and signatures grow) |
| **Network** | Needed for signature and product updates, and for JagAI |
| **Privileges** | Administrator for the MSI and for Windows Firewall changes |

Kernel drivers are not included. You do not need a signed driver or WDK for this MSI.

---

## Install on Windows

1. Download the MSI from **[tpjsecurity.com/download](https://tpjsecurity.com/download)**.
2. Right-click the installer and choose **Run as administrator**.
3. Finish the wizard. Default directory: `C:\Program Files\TrueProtection`.
4. The installer registers the **True Protection Daemon** service (`TpjDaemon`), puts `C:\Program Files\TrueProtection\bin` on PATH, and can launch the Qt GUI.

There is no winget, Chocolatey, or Store package for this release.

---

## Verify the install

Open an elevated Command Prompt:

```text
tpj --version
```

You should see **1.2.66** (or the version printed on the download page if a newer desktop tag has shipped).

```text
tpj status
```

When the daemon is running, status includes version, overall status, firewall, scanner, and related fields. If you see `Status: Not connected`, start the service (below).

```text
tpj firewall list
```

`tpj firewall show` is not a command.

---

## First run

On first launch the GUI connects to the daemon over a named pipe.

| Setting | Default in this MSI |
|---|---|
| Daemon service | `TpjDaemon`, automatic start |
| Firewall default inbound | Ask (no Windows Firewall writes until you pick Allow or Block) |
| Firewall default outbound | Ask |
| GUI | Qt desktop (`tpj-gui`) |
| CLI | `tpj` on PATH |

Change firewall policy in **Settings > Firewall**, or see the [Firewall guide](firewall.md). Other options live on the Settings pages in the GUI. Do not rely on undocumented `tpj config` flags.

### Data locations (Windows)

| What | Path |
|---|---|
| Program files | `C:\Program Files\TrueProtection\` |
| Program data, signatures, quarantine | `C:\ProgramData\TrueProtection\` |

---

## The daemon service

The CLI and GUI both need `tpj-daemon` running.

```text
sc query TpjDaemon
net start TpjDaemon
net stop TpjDaemon
```

Display name: **True Protection Daemon**. Account: LocalSystem. Start type: automatic.

---

## Run a scan

```text
tpj scan
tpj scan --scan-type quick
tpj scan --scan-type full
tpj scan --scan-type custom C:\Path\To\Folder
```

`tpj scan` defaults to `quick`. You can also start a scan from the GUI Scan page.

After a scan, the CLI prints files scanned, clean, skipped, and any threats. Use `tpj quarantine list` if items were quarantined.

This scanner is user-mode hash and heuristic matching. It is not ClamAV, native YARA, or a kernel on-access minifilter.

Full scan details: [Scanning Guide](scanning.md).

---

## Firewall

Open **Firewall** in the GUI, or:

```text
tpj firewall list
tpj firewall add --name "Allow HTTPS" --action allow --direction outbound --protocol tcp --port 443
tpj firewall delete <RULE_ID>
tpj firewall toggle on
```

Rules are INetFw / Windows Firewall, not WFP. Defaults stay at Ask until you opt into Allow or Block. DNS and DHCP appear as daemon catalog keys (`dns`, `dhcp`), not as a DNS or DHCP server product. There is no Mail Security, anti-spam, or WAF/ModSecurity module. See [Firewall](firewall.md).

---

## JagAI (optional)

JagAI is the paid analysis add-on (Powered by JagAI). It is not required for the free engine.

1. Sign in at **[tpjsecurity.com](https://tpjsecurity.com)**.
2. Choose a paid plan if you want JagAI.
3. Use the in-app JagAI / account UI after the license is active.

There is no 14-day trial.

---

## Uninstall

**Settings > Apps > True Protection by Jag > Uninstall**, or uninstall from the MSI.

This removes the service and program files. Data under `C:\ProgramData\TrueProtection\` may remain until you delete it.

---

## Next Steps

- [Understanding the Dashboard](dashboard.md) - status in the Qt GUI and CLI
- [Scanning Guide](scanning.md) - scan types and results
- [Firewall](firewall.md) - INetFw rules, live connections, CLI verbs
- [JagAI Module](jagai-module.md) - paid analysis
- [CLI Reference](../../04-reference/cli-reference.md) - command list
- [Configuration Reference](../../04-reference/configuration.md) - file layout
