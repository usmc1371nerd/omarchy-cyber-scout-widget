# Cyber Scout LAN Observer

Cyber Scout is a local-first Omarchy toolbar widget and loopback dashboard for
observing devices on the networks currently attached to the computer. It keeps
active diagnostics explicit, bounded, and limited to approved local targets.

## Current features

- Dynamic current-network scoping across attached Ethernet and Wi-Fi interfaces.
- Passive Linux neighbor-table and local-interface observations.
- Optional, explicitly initiated Nmap discovery with progress and cancellation.
- Persistent SQLite inventory, address history, events, recognition, categories,
  names, notes, services, and diagnostic history.
- Queued ping, common-service, and selected safety-port checks.
- Compact Omarchy/Quickshell interface with search and device actions.
- Loopback-only dashboard on `http://127.0.0.1:8765` with current-device
  details, timeline, search, filtering, JSON exports, and validated settings.
- Optional Zeek JSON and Suricata EVE metadata ingestion with cursor tracking,
  alert deduplication, source status, and explicit visibility limits.
- Connection-aware public IP/ISP lookup that never presents a previous network's
  cached provider as current.
- No telemetry, analytics, cloud account, packet payload storage, or remote bind.

## Install on Omarchy

```bash
omarchy plugin add https://github.com/usmc1371nerd/omarchy-cyber-scout-widget.git --enable
```

Open the LAN Devices icon in the Omarchy bar. The circular arrow performs an
explicit local discovery. Device diagnostics run only when selected. Use
**Open Cyber Scout Dashboard** for the larger local view.

## Runtime data

- SQLite: `~/.local/share/cyber-scout/cyber-scout.db`
- Compatibility cache: `~/.cache/omarchy-lan-devices.json`
- WAN cache: `~/.cache/omarchy-lan-wan.json`
- User aliases: `~/.local/share/omarchy-lan-devices/names.json`

Runtime databases, caches, and user-specific observations are not stored in
this repository.

## Optional deep monitoring

Cyber Scout does not install, start, or grant capture privileges to Zeek or
Suricata. If either sensor is already configured, enter absolute paths in the
dashboard settings:

- Zeek JSON log directory containing `conn.log` and/or `notice.log`.
- Suricata EVE JSON file, commonly `eve.json`.

The monitor reads only appended complete JSON lines, caps work per cycle, and
tracks inode and byte offsets across rotation. It stores connection/alert
metadata from a strict allowlist; raw packets, printable payloads, HTTP bodies,
and file content are discarded. A normal switched Ethernet or Wi-Fi host sees
only traffic delivered to it. Full-LAN visibility requires a mirror port,
network tap, or gateway-based sensor.

## Development

The backend uses Python's standard library. Tests require `pytest`.

```bash
python3 -B -m py_compile scanner.py cyber_scout/*.py
python3 -B -m pytest -q -p no:cacheprovider tests
```

Operational installation, configuration, logging, database recovery, optional
user services, testing, release construction, and rollback are documented in
[OPERATIONS.md](OPERATIONS.md). The optional services are never installed or
enabled automatically.

See [ROADMAP.md](ROADMAP.md) for stage status and
[ARCHITECTURE.md](ARCHITECTURE.md) for discovery, identity, privilege, and
visibility boundaries.

## Safety boundary

Cyber Scout is intended only for networks the user owns or is authorized to
inspect. Passive display scope follows attached interfaces dynamically. Active
scans are a separate capability: disabled by default, restricted to local
private ranges, bounded, and never run silently against public networks.
