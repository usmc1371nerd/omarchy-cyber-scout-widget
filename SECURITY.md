# Security policy and operating boundary

Cyber Scout is intended for networks the user owns or is authorized to inspect.
Report suspected vulnerabilities privately to the repository owner before
public disclosure.

## Security properties

- The dashboard binds only to loopback and validates local write requests with
  a per-process token.
- Active probes are explicit, bounded, argv-based, and restricted to private
  current-network targets.
- Passive monitoring and the dashboard run without root privileges.
- Packet payload capture, remote dashboard binding, telemetry, and cloud
  accounts are not part of the core product.
- Runtime configuration, inventory, backups, and logs are user-private.

## Sensitive reports

Include the affected commit, reproduction steps, impact, and suggested fix when
possible. Do not include real device inventories, MAC addresses, public IPs,
database files, or unredacted logs in public issues.
