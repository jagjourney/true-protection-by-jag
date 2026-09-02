# Firewall

The current Windows MSI manages **Windows Firewall** in user mode through INetFw. You work with it in the Qt **Firewall** page or with the `tpj firewall` CLI. There is no WFP callout, eBPF backend, macOS Network Extension, or deep packet inspection in this build.

Linux pipeline DEB and RPM packages use the same `tpj firewall` CLI. The daemon programs **nftables**. That is not INetFw, not eBPF, and Linux is not a Supported launch platform. On a host without Qt, the CLI is the UI.

The daemon (`TpjDaemon`) holds the rule list. When the default policy is **Allow** or **Block**, matching rules are written to Windows Firewall as `TPJ_*` rules. When both directions are **Ask** (the default), True Protection evaluates rules in-engine only and does **not** program Windows Firewall until you change policy or approve a decision.

---

## Table of Contents

- [Open the Firewall page](#open-the-firewall-page)
- [Default policy (Ask, Allow, or Block)](#default-policy-ask-allow-or-block)
- [Rules in the GUI](#rules-in-the-gui)
- [Live connections](#live-connections)
- [Pending decisions](#pending-decisions)
- [CLI](#cli)
  - [tpj firewall list](#tpj-firewall-list)
  - [tpj firewall add](#tpj-firewall-add)
  - [tpj firewall delete](#tpj-firewall-delete)
  - [tpj firewall toggle](#tpj-firewall-toggle)
  - [tpj firewall policy](#tpj-firewall-policy)
  - [tpj firewall purge](#tpj-firewall-purge)
- [Suggested rules](#suggested-rules)
- [Clear TPJ rules from Windows Firewall](#clear-tpj-rules-from-windows-firewall)
- [Troubleshooting](#troubleshooting)

---

## Open the Firewall page

1. Start **True Protection** (`tpj-gui`).
2. Open **Firewall** from the toolbar or the Firewall menu.
3. Confirm the daemon is connected. If the page says it is disconnected, start the **True Protection Daemon** service (`TpjDaemon`) from an elevated prompt.

The page shows:

- **Enable Firewall** toggle
- **Firewall Rules** table (Name, Action, Direction, Protocol, Port, Application, Enabled) with Add / Edit / Delete
- **Active Connections** table (PID, process, protocol, local, remote, country, state) with a per-row Block button
- **Pending Decisions** when a default policy is Ask
- Auto-blocked IPs with **Unblock Selected**

---

## Default policy (Ask, Allow, or Block)

Set these in **Settings > Firewall**, or with `tpj firewall policy`.

| Policy | What it does |
|---|---|
| **Ask** (default for inbound and outbound) | Rules stay in True Protection. Nothing is written to Windows Firewall until you pick Allow or Block, or you answer a pending decision with Allow Always / Block Always. |
| **Allow** | Traffic is allowed by default. Block rules are pushed to Windows Firewall. |
| **Block** | Traffic that does not match an Allow rule is dropped in Windows Firewall. |

Both directions start at Ask so a first install does not rewrite the host firewall.

---

## Rules in the GUI

The **Firewall Rules** table is the same list `tpj firewall list` prints.

- **Add** prompts for a name, then creates a block / inbound / tcp rule. Open **Edit** immediately to set action, direction, protocol, port, and application.
- **Edit** opens the full rule form (name, action, direction, protocol, port, application, enabled).
- **Delete** removes the selected rule from the daemon. If OS-sync is on (Allow or Block), the matching `TPJ_*` Windows Firewall rule is removed too.

Application paths are Windows paths, for example `C:\Program Files\Mozilla Firefox\firefox.exe`.

---

## Live connections

The Active Connections table refreshes about every two seconds. Use the filter box to match a process or remote address. **Block** on a row creates a persistent block rule for that remote IP and port.

---

## Pending decisions

When inbound or outbound policy is Ask and a connection matches no rule, it can appear under **Pending Decisions** (process, direction, protocol, remote, time). Answer **Allow**, **Block**, **Allow Always**, or **Block Always**. The Always choices insert a persistent rule so the same tuple is not prompted again.

---

## CLI

Run these from an elevated prompt so the CLI can reach `tpj-daemon`. The supported verbs are `list`, `add`, `delete`, `toggle`, plus `policy` and `purge`. There is no `tpj firewall show` command. Use `list`.

### tpj firewall list

```text
tpj firewall list
```

Columns: ID, NAME, ACTION, DIR, PROTO, ENABLED.

Default seed IDs look like `dns`, `http`, `https`, `dhcp`. Those are ordinary INetFw catalog keys in the daemon (Allow DNS UDP 53, Allow HTTP TCP 80, Allow HTTPS TCP 443, Allow DHCP UDP 67-68). They are not a DNS or DHCP server product. User-added IDs are `user-` plus the rule name. Copy the ID from this table for `delete`.

### tpj firewall add

```text
tpj firewall add --name "Allow HTTPS" --action allow --direction outbound --protocol tcp --port 443

tpj firewall add --name "Block Telnet" --action block --direction inbound --protocol tcp --port 23

tpj firewall add --name "Block App" --action block --direction both --app "C:\Path\app.exe"
```

| Flag | Values | Default |
|---|---|---|
| `--name` | Any string | Required |
| `--action` | `allow` or `block` | Required |
| `--direction` | `inbound`, `outbound`, `both` | `both` |
| `--protocol` | `tcp`, `udp`, `any` | `any` |
| `--port` | 1-65535 | All ports |
| `--app` | Executable path | All apps |

### tpj firewall delete

```text
tpj firewall delete https
tpj firewall delete user-Block-Telnet
```

Pass the ID from `tpj firewall list`, not a display name.

### tpj firewall toggle

```text
tpj firewall toggle on
tpj firewall toggle off
```

Same intent as the **Enable Firewall** checkbox. `on`, `enable`, and `true` turn it on; anything else is treated as off.

### tpj firewall policy

```text
tpj firewall policy --inbound ask --outbound ask
tpj firewall policy --inbound block --outbound allow
```

Values: `ask`, `allow`, `block`. Same store as Settings > Firewall. If both directions are Ask, the CLI reminds you that no rules are pushed to Windows Firewall.

### tpj firewall purge

```text
tpj firewall purge
```

Removes every `TPJ_*` rule from Windows Firewall. Custom rules you created in Windows Firewall itself are left alone. Use this if an older build stacked duplicate TPJ rules.

---

## Suggested rules

The Firewall page lists optional one-click rules (block inbound RDP, block Telnet, block outbound SMB, and similar). Each toggle adds or removes a named rule in the daemon. They are ordinary INetFw rules when OS-sync is on, not kernel-driver rules. There is no visual-editor template library in this MSI, and there is no Mail Security, anti-spam, or WAF/ModSecurity template.

---

## Clear TPJ rules from Windows Firewall

Same cleanup as `tpj firewall purge`:

1. Open **Settings > Firewall**.
2. Click **Clear all TPJ rules from Windows Firewall**.
3. Confirm. Only names that start with `TPJ_` are removed.

---

## Troubleshooting

### Daemon not connected

```text
sc query TpjDaemon
net start TpjDaemon
tpj status
```

The service display name is **True Protection Daemon**. The CLI talks to it over a named pipe. If `tpj firewall list` fails, start the service from an elevated prompt.

### Rules exist in the GUI but not in Windows Firewall

Default policy is Ask. Open Settings > Firewall and set inbound or outbound to Allow or Block, or answer a pending decision with Allow Always / Block Always.

### An app cannot connect

1. `tpj firewall list` and look for a block on that app or port.
2. Check default policy. Block outbound with no matching allow rule will drop it.
3. Check Pending Decisions and Auto-Blocked IPs on the Firewall page.

### Too many TPJ_* rules in Windows Firewall

Run `tpj firewall purge` or use the Settings button above. Then set policy again if you want OS-sync.

### This is not a kernel firewall

If Windows Firewall itself is off, True Protection cannot enforce at the host until you turn Windows Firewall on. Kernel WFP is not in this MSI.
