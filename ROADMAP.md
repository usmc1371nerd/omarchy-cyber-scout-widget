# Development stages

Status legend: ✅ complete · 🚧 in progress · ⬜ planned

## ✅ Stage 1 — Audit

- Inspected the original QML widget and Python scanner.
- Documented discovery mechanisms, dependencies, persistence, process model,
  limitations, and privilege boundaries.
- Preserved the existing compact visual identity and argv-based JSON contract.

## ✅ Stage 2 — Foundation

- Versioned SQLite schema and transactional migrations.
- Stable exact-MAC identity with conservative merge rules.
- IPv4/IPv6 address, hostname, observation, service, and event history.
- Recognition state, categories, notes, names, confidence, and retention.
- Passive neighbor-table reconciliation and Netlink neighbor-event parsing.
- Dynamic display scope derived from currently attached interfaces.
- Automated parser, identity, history, migration, and validation tests.

## ✅ Stage 3 — Usability

- Search and recognition filtering in the compact widget.
- Expandable device cards and explicit user-managed metadata.
- Plain-English deterministic diagnostic explanations.
- Accurate observed-versus-active semantics and current-network counts.
- Connection-aware WAN public-IP/ISP information.

## ✅ Stage 4 — Diagnostics

- Durable queued diagnostic jobs with bounded single-worker execution.
- Ping, common-service, and selected safety-port checks.
- Target validation, structured results, progress, timeout handling, and
  cooperative cancellation.
- Manual active-discovery jobs with fixed commands, rate/time bounds, progress,
  cancellation, overlap prevention, and private `/24` maximum scope.
- Scheduled scan authorization gates implemented; scheduling remains disabled
  by default.

## 🚧 Stage 5 — Full dashboard

Completed:

- Loopback-only, read-only standard-library HTTP server.
- Current-network overview, inventory, search, recognition filter, and timeline.
- Evidence-backed device details, services, diagnostics, and events.
- Per-device and current-inventory JSON downloads.
- Security headers and no fixture data in production views.

Remaining:

- Settings UI and safely validated write endpoints.
- Security-center acknowledgement and dismissal controls.
- Richer change-period selection, reporting, and trends.
- Historical-inventory opt-in view clearly separated from current devices.
- Local-host multi-interface presentation as one physical machine.

## ⬜ Stage 6 — Deep monitoring

- Optional Zeek structured-log ingestion.
- Optional Suricata EVE JSON ingestion and alert deduplication.
- Sensor visibility/status reporting and mirrored-port limitations.
- Packet payload storage remains disabled by default.

## 🚧 Stage 7 — Hardening and packaging

Completed:

- Safe argv subprocess execution and bounded commands.
- Loopback-only dashboard and current-network API scoping.
- Local file permissions, WAL SQLite, indexes, retention, and input validation.
- Graceful optional-tool failures and automated regression suite.

Remaining:

- Complete installation, configuration, security, testing, and rollback guides.
- User-systemd units after explicit installation approval.
- Structured log rotation, resource-limit verification, and migration recovery.
- Broader fixtures, integration tests, and release packaging.
