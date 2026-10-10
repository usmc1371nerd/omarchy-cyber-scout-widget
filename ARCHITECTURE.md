# Cyber Scout LAN Observer Architecture

## Current implementation found during audit

Cyber Scout currently exists as the user-owned Omarchy plugin
`hackerdad.lan-devices`. It is loaded by the Omarchy Shell because its plugin ID
appears in `~/.config/omarchy/shell.json`.

The runtime path is:

1. `BarWidget.qml` creates the toolbar button and lazily loads `Panel.qml`.
2. `Panel.qml` uses Quickshell `Process` objects to invoke `scanner.py`.
3. `scanner.py` prints one JSON object to stdout.
4. QML parses that object and renders the compact device list.

There is no daemon, local API, listening socket, package manifest, background
worker, or privileged helper. Everything runs with the logged-in desktop
user's authority.

### Existing discovery mechanisms

Passive refresh currently uses:

- `ip -j route show default` and `ip -j address show dev <interface>` to select
  one active IPv4 interface, subnet, local address, and gateway.
- `ip neigh show dev <interface>` to read the kernel neighbor table.
- `/sys/class/net/<interface>/address` for the local interface MAC.
- local Nmap or hwdata OUI files for manufacturer lookup.
- the prior JSON discovery cache, which is merged into every passive result.

The old passive result is not a complete discovery view. It is also not a
reliable online-state view because cached rows and `STALE` neighbor entries are
not clearly distinguished from recently confirmed neighbors.

Explicit active operations currently use:

- `nmap -sn -n <network>` for discovery.
- `ping` for ICMP diagnostics.
- `avahi-resolve-address` for targeted mDNS lookup.
- bounded Nmap TCP scans for common services and selected safety ports.
- a fixed HTTPS request to `ipwho.is` for optional WAN IP/ISP lookup.

Active discovery is initiated by the refresh button or middle click. It is
not scheduled. Targets are checked against the selected local IPv4 network.

### Existing persistence

The original implementation uses flat JSON files:

- `~/.cache/omarchy-lan-devices.json`
- `~/.cache/omarchy-lan-wan.json`
- `~/.local/share/omarchy-lan-devices/names.json`

These preserve the current display cache and user aliases but do not model
stable device identity, multiple addresses, history, events, services,
recognition, notes, or retention.

## Audit conclusions and limitations

- The UI and subprocess calls use argv arrays rather than a shell. Current
  target validation prevents diagnostic targets outside the active IPv4 LAN.
- IPv6 is present on the host but ignored by the original inventory.
- Device identity is effectively IP-first and cannot safely represent DHCP
  churn, IP reuse, randomized MAC addresses, or multiple interfaces.
- `-n` disables name resolution in active Nmap discovery, so the Nmap report
  parser does not normally obtain hostnames.
- Generic service discovery ignores the Nmap exit status and may describe a
  failed check as an empty result.
- Discovery progress and cancellation do not exist. QML only prevents one
  scan process and one action process from overlapping inside one panel.
- OUI data is reparsed for every short-lived Python invocation.
- Cached devices are carried forward indefinitely without retention or an
  explicit historical state.
- No packet observation, DHCP observation, SSDP observation, Netlink event
  stream, Zeek ingestion, or Suricata ingestion exists.
- The current host has `ip`, Nmap, ping, Avahi, SQLite, pytest, tcpdump, and
  tshark. It does not currently have arp-scan, Zeek, Suricata, FastAPI,
  Uvicorn, pyroute2, Scapy, or zeroconf.

The Stage 1 Codex Security scan found no reportable privilege-boundary
vulnerability in the current local-only plugin. Correctness, privacy, state
validation, and least-privilege controls must be strengthened before adding a
daemon or web API.

## Selected architecture

The existing QML widget and `scanner.py` JSON contract remain the compatibility
surface. New backend behavior is implemented in the standard-library Python
package `cyber_scout` beside the existing files.

```text
Omarchy bar / Panel.qml
          |
          | argv + JSON stdout (backward-compatible)
          v
      scanner.py
          |
          +-- PassiveDiscoveryManager
          |     +-- LocalInterfaceAdapter
          |     +-- NeighborTableAdapter
          |     +-- future event adapters
          |
          +-- ActiveDiagnosticEngine (existing bounded actions first)
          |
          +-- InventoryStore (SQLite migrations and transactions)
          |
          +-- future localhost API and dashboard
```

### Identity rules

- An exact normalized MAC address is currently the only automatic cross-address
  merge key for other devices.
- The local machine may additionally use an explicit local-host identity in a
  later migration.
- An address without a MAC is retained as an unassigned observation. It is not
  automatically merged into a device based only on IP, hostname, or vendor.
- Locally administered MAC addresses are marked as potentially randomized and
  receive lower identification confidence. They remain distinct exact-MAC
  identities unless a user explicitly corrects them in a later stage.
- IPv4 and IPv6 addresses are stored independently and may belong to the same
  exact-MAC device.

### Observation and availability semantics

- `last_observed` means a sensor produced an observation.
- `last_active` is updated only for a state that supplies stronger recent
  activity evidence, such as `REACHABLE`, `DELAY`, or `PROBE`.
- A `STALE` neighbor is an observation but not proof of current activity.
- A timeout or failed neighbor entry is not proof that a device is offline.
- Active diagnostic success is stored separately from passive observation.

### Persistent storage

The SQLite database is stored at
`~/.local/share/cyber-scout/cyber-scout.db`, with its directory restricted to
the user. Schema changes use `PRAGMA user_version` migrations and transactions.
The initial schema contains devices, addresses, hostname history,
observations, services, events, and settings with indexes for common timeline
and inventory queries.

Schema version 2 adds durable diagnostic jobs. The compact widget submits a
validated device ID, an address already associated with that device, and one
of three fixed job kinds (`ping`, `services`, or `exposure`). A detached
unprivileged worker uses a user-owned file lock to enforce one active job at a
time, processes queued work in order, applies fixed commands/timeouts, polls
for cancellation, and stores structured results. No command text, arbitrary
target, Nmap option, or process ID is accepted from the UI.

Diagnostic timeouts and ICMP silence are stored as inconclusive rather than as
proof that a device is offline. Successful connectivity checks update the
separate `last_connectivity` field. Service and safety-port results populate
service history and deterministic plain-English explanations.

Schema version 3 adds active-discovery scan jobs. A manual scan is authorized
by the user's Discover action and is always reduced to the currently
configured private IPv4 interface range, with a maximum `/24` scope. The
worker applies fixed Nmap host-discovery arguments, a configured maximum rate,
bounded per-host and total timeouts, single-worker overlap protection,
progress updates, and cooperative cancellation. Completion triggers passive
neighbor reconciliation; nonresponses are never converted into offline state.

Optional scheduled scans use the same queue and worker but require three
independent gates: `active_discovery_enabled`, a nonzero
`scheduled_scan_minutes`, and an explicitly listed private approved range that
contains an address currently assigned to the selected interface. All three
defaults prevent scheduled scanning. Merely starting the passive monitor does
not authorize an active scan.

The old JSON files remain readable during compatibility migration. They are
not deleted or destructively transformed.

### Foundation status

Implemented foundation components now include:

- periodic reconciliation from `ip -j address` and `ip -j neigh`;
- an event parser and long-running observer for the non-probing
  `ip monitor neigh` Netlink stream;
- exact-MAC identity, IPv4/IPv6 address history, hostname history, observation
  history, debounced change events, recognition state, categories, notes, and
  user-managed names;
- validated local configuration with active scanning off and no approved
  ranges by default;
- retention pruning that removes old observations/events without deleting the
  device inventory;
- a single-instance passive monitor with graceful signal handling; and
- backward-compatible widget JSON enriched with stable device IDs, activity
  timestamps, recognition state, confidence, and compact inventory counts.

The passive monitor is available as `python3 -B -m cyber_scout.monitor`. It is not
installed as a persistent service yet. Service installation is deliberately
deferred until its exact user-unit files and operational impact can be
presented for approval.

mDNS browsing, SSDP listening, DHCP observation, and packet-derived connection
metadata are not implemented yet. They must remain separate adapters because
their availability and privilege/visibility requirements differ. In
particular, an mDNS browse operation that transmits multicast queries must not
be mislabeled as passive observation.

## Planned stages

1. **Foundation:** SQLite migrations, strict identity handling, typed passive
   adapters, event history, and automated tests.
2. **Usability:** recognition/category/note controls, accurate activity states,
   plain-English deterministic findings, filtering, and compact status counts.
3. **Diagnostics:** queued bounded jobs, approved ranges, progress,
   cancellation, scheduling, and diagnostic history.
4. **Dashboard:** a localhost-only API and functional local frontend with
   inventory, timeline, security center, settings, export, and deletion.
5. **Deep monitoring:** optional Zeek and Suricata JSON ingestion. The core
   application remains functional without either dependency.
6. **Hardening:** retention, structured logging, resource limits, migration
   recovery, packaging, service isolation, and complete documentation.

## Privilege and visibility boundaries

The core inventory and current diagnostics run unprivileged. Packet capture is
not enabled by this foundation. Any future capture helper or capability change
must be narrowly scoped and requires explicit approval before installation.

A normal Wi-Fi or switched Ethernet interface cannot observe all traffic
between other LAN devices. Connection views must label their sensor source and
must never imply full-LAN visibility unless the host is attached to a mirror
port, network tap, supported gateway sensor, or equivalent observation point.

The first dashboard increment is implemented with the Python standard library
and binds only to `127.0.0.1:8765`. It is read-only and exposes fixed routes for
the real inventory, 24-hour overview, and event timeline; it performs no probes
and includes no fixture data. The widget starts it on demand through the
Dashboard button. The second increment adds evidence-backed device detail views
covering address history, services, diagnostics, and per-device events, plus
downloadable device and full-inventory JSON reports. Export data is generated
locally from SQLite and contains no inferred or mock observations. LAN binding,
write APIs, authentication, system services, firewall changes, new packages,
and packet capture capabilities remain separate approval-gated operations.

Current-inventory visibility is dynamically scoped from live
`ip -j address show` and default-route data on each widget refresh and each API
request. All attached IPv4 interface networks are included without hardcoded
CIDRs. Devices from disconnected networks remain historical database evidence
but are excluded from default counts, inventory, timelines, detail access, and
JSON exports. Active scanning retains its separate private, approved-target
restrictions and does not inherit this display-only scope.
