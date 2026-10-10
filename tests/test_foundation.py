from __future__ import annotations

import sqlite3

from cyber_scout.config import ConfigManager, CyberScoutConfig
from cyber_scout.database import InventoryStore, SCHEMA_VERSION
from cyber_scout.discovery import NeighborEventAdapter, NeighborTableAdapter
from cyber_scout.diagnostics import explain_open_port, summarize_findings
from cyber_scout.dashboard import dashboard_snapshot
from cyber_scout.jobs import command_for, parse_result
from cyber_scout import jobs
from cyber_scout.scheduling import approved_local_scan_targets
from cyber_scout.models import Observation, is_locally_administered, normalize_mac
from cyber_scout.scope import current_ipv4_scopes


def test_mac_normalization_and_randomized_detection() -> None:
    assert normalize_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"
    assert normalize_mac("not-a-mac") is None
    assert is_locally_administered("02:00:00:00:00:01")
    assert not is_locally_administered("00:11:22:33:44:55")


def test_exact_mac_deduplicates_and_records_ip_change(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        first = Observation("neighbor_table", "eth0", "192.168.1.10", "00:11:22:33:44:55", observed_at=100)
        second = Observation("neighbor_table", "eth0", "192.168.1.20", "00:11:22:33:44:55", observed_at=200)
        assert store.ingest(first) == store.ingest(second)
        assert store.connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1
        assert store.connection.execute("SELECT COUNT(*) FROM addresses").fetchone()[0] == 2
        assert store.connection.execute(
            "SELECT COUNT(*) FROM events WHERE event_type = 'device.address_added'"
        ).fetchone()[0] == 1


def test_address_without_mac_is_not_merged_into_device(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        observation = Observation("mdns", "eth0", "192.168.1.30", hostname="speaker.local", observed_at=100)
        assert store.ingest(observation) is None
        assert store.connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0
        assert store.connection.execute("SELECT COUNT(*) FROM observations").fetchone()[0] == 1


def test_stale_neighbor_is_observed_but_not_active(tmp_path) -> None:
    rows = [{"dst": "192.168.1.40", "dev": "eth0", "lladdr": "00:11:22:33:44:66", "state": ["STALE"]}]
    observations = NeighborTableAdapter.parse(rows, 123)
    assert len(observations) == 1
    assert not observations[0].active
    with InventoryStore(tmp_path / "inventory.db") as store:
        device_id = store.ingest(observations[0])
        row = store.connection.execute("SELECT last_observed, last_active FROM devices WHERE id = ?", (device_id,)).fetchone()
        assert row["last_observed"] == 123
        assert row["last_active"] is None


def test_failed_neighbor_is_not_treated_as_device() -> None:
    rows = [{"dst": "192.168.1.50", "dev": "eth0", "state": ["FAILED"]}]
    assert NeighborTableAdapter.parse(rows, 123) == []


def test_neighbor_event_parser_handles_activity_and_unsafe_states() -> None:
    observed = NeighborEventAdapter.parse_line(
        "192.168.1.44 dev wlp1s0 lladdr aa:bb:cc:dd:ee:ff REACHABLE", 123
    )
    assert observed is not None
    assert observed.source == "neighbor_event"
    assert observed.active
    assert observed.mac == "AA:BB:CC:DD:EE:FF"
    assert NeighborEventAdapter.parse_line(
        "Deleted 192.168.1.44 dev wlp1s0 lladdr aa:bb:cc:dd:ee:ff STALE", 123
    ) is None
    assert NeighborEventAdapter.parse_line(
        "192.168.1.44 dev wlp1s0 lladdr aa:bb:cc:dd:ee:ff FAILED", 123
    ) is None


def test_schema_migration_is_idempotent(tmp_path) -> None:
    path = tmp_path / "inventory.db"
    with InventoryStore(path):
        pass
    with InventoryStore(path) as store:
        version = store.connection.execute("PRAGMA user_version").fetchone()[0]
        assert version == SCHEMA_VERSION
        assert path.stat().st_mode & 0o777 == 0o600


def test_newer_schema_is_rejected(tmp_path) -> None:
    path = tmp_path / "inventory.db"
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA user_version = 99")
    connection.close()
    try:
        InventoryStore(path)
    except RuntimeError as error:
        assert "newer than supported" in str(error)
    else:
        raise AssertionError("newer schema should be rejected")


def test_configuration_is_local_only_and_active_scanning_defaults_off(tmp_path) -> None:
    manager = ConfigManager(tmp_path / "config.json")
    default = manager.load()
    assert not default.active_discovery_enabled
    assert default.approved_networks == ()
    assert not default.allows_target("192.168.1.10")

    config = CyberScoutConfig(approved_networks=("192.168.1.0/24", "fe80::/64"))
    manager.save(config)
    loaded = manager.load()
    assert loaded.allows_target("192.168.1.10")
    assert loaded.allows_target("fe80::1")
    assert not loaded.allows_target("8.8.8.8")
    assert manager.path.stat().st_mode & 0o777 == 0o600


def test_public_scan_network_is_rejected() -> None:
    try:
        CyberScoutConfig.from_mapping({"approved_networks": ["8.8.8.0/24"]})
    except ValueError as error:
        assert "private or link-local" in str(error)
    else:
        raise AssertionError("public scan range should be rejected")


def test_enrichment_preserves_user_category(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        observation = Observation("neighbor_table", "eth0", "192.168.1.1", "00:11:22:33:44:55", observed_at=100)
        device_id = store.ingest(observation)
        assert store.enrich_device_by_mac(
            "00:11:22:33:44:55", user_name="Gateway", manufacturer="Example", category="Router"
        )
        store.connection.execute("UPDATE devices SET category = 'Server' WHERE id = ?", (device_id,))
        store.connection.commit()
        store.enrich_device_by_mac("00:11:22:33:44:55", category="Router")
        row = store.connection.execute(
            "SELECT user_name, manufacturer, category FROM devices WHERE id = ?", (device_id,)
        ).fetchone()
        assert tuple(row) == ("Gateway", "Example", "Server")


def test_device_management_and_change_queries(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        device_id = store.ingest(
            Observation("neighbor_table", "eth0", "192.168.1.20", "00:11:22:33:44:55", observed_at=100)
        )
        updated = store.update_device(
            device_id, user_name=" Office   computer ", category="Computer",
            recognition="recognized", notes="Trusted workstation", occurred_at=200,
        )
        assert updated["user_name"] == "Office computer"
        assert updated["recognition"] == "recognized"
        assert store.list_devices(search="office", recognition="recognized")[0]["id"] == device_id
        summary = store.change_summary(0, 300)
        assert summary["counts"]["device.first_observed"] == 1
        assert summary["counts"]["device.user_updated"] == 1
        assert store.get_device_by_mac("00:11:22:33:44:55")["id"] == device_id


def test_invalid_device_management_values_are_rejected(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        device_id = store.ingest(
            Observation("neighbor_table", "eth0", "192.168.1.20", "00:11:22:33:44:55", observed_at=100)
        )
        for field, value in (("category", "Laptop"), ("recognition", "evil")):
            try:
                store.update_device(device_id, **{field: value})
            except ValueError:
                pass
            else:
                raise AssertionError(f"invalid {field} should be rejected")


def test_notes_are_sanitized_and_bounded(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        device_id = store.ingest(
            Observation("neighbor_table", "eth0", "192.168.1.20", "00:11:22:33:44:55", observed_at=100)
        )
        assert store.update_device(device_id, notes="  Office\n workstation  ")["notes"] == "Office workstation"
        try:
            store.update_device(device_id, notes="x" * 2001)
        except ValueError as error:
            assert "2000" in str(error)
        else:
            raise AssertionError("oversized notes should be rejected")


def test_retention_prunes_history_not_inventory(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        store.ingest(Observation("neighbor_table", "eth0", "192.168.1.20", "00:11:22:33:44:55", observed_at=100))
        removed = store.prune(1, now=200000)
        assert removed["observations"] == 1
        assert removed["events"] == 1
        assert store.connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1


def test_service_history_and_event_deduplication(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        store.ingest(Observation("neighbor_table", "eth0", "192.168.1.20", "00:11:22:33:44:55", observed_at=100))
        services = [{"port": 22, "protocol": "tcp", "service": "SSH"}]
        assert store.record_services_for_address("192.168.1.20", services, source="test", observed_at=200) == 1
        assert store.record_services_for_address("192.168.1.20", services, source="test", observed_at=300) == 1
        assert store.connection.execute("SELECT COUNT(*) FROM services").fetchone()[0] == 1
        assert store.connection.execute("SELECT COUNT(*) FROM events WHERE event_type='device.service_added'").fetchone()[0] == 1


def test_plain_english_port_explanation_separates_evidence_and_advice() -> None:
    finding = explain_open_port(23, "Telnet", "higher")
    assert "accepted a connection" in finding["observation"]
    assert "without encryption" in finding["meaning"]
    assert finding["technicalDetails"] == {"protocol": "tcp", "port": 23, "service": "Telnet", "state": "open"}
    assert "not confirmation" in summarize_findings([finding])


def test_diagnostic_queue_deduplicates_and_cancels(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        device_id = store.ingest(
            Observation("neighbor_table", "eth0", "192.168.1.20", "00:11:22:33:44:55", observed_at=100)
        )
        first = store.queue_diagnostic(device_id, "192.168.1.20", "exposure", now=200)
        second = store.queue_diagnostic(device_id, "192.168.1.20", "exposure", now=201)
        assert first["id"] == second["id"]
        assert store.claim_next_diagnostic(now=202)["status"] == "running"
        assert store.request_diagnostic_cancel(first["id"], now=203)["cancel_requested"]
        assert store.diagnostic_cancel_requested(first["id"])
        finished = store.finish_diagnostic(first["id"], "cancelled", error="Cancelled", now=204)
        assert finished["status"] == "cancelled"


def test_diagnostic_queue_rejects_wrong_device_address(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        device_id = store.ingest(
            Observation("neighbor_table", "eth0", "192.168.1.20", "00:11:22:33:44:55", observed_at=100)
        )
        try:
            store.queue_diagnostic(device_id, "192.168.1.99", "ping")
        except ValueError as error:
            assert "does not belong" in str(error)
        else:
            raise AssertionError("cross-device target should be rejected")


def test_diagnostic_command_and_result_parsing_are_bounded() -> None:
    job = {"kind": "services", "address": "192.168.1.20"}
    command, timeout = command_for(job)
    assert command[-1] == "192.168.1.20"
    assert command[:3] == ["nmap", "-sT", "-n"]
    assert timeout <= 14
    result = parse_result("services", "22/tcp open ssh\n80/tcp open http\n", 0)
    assert result["services"][0] == {"port": 22, "protocol": "tcp", "service": "ssh"}


def test_worker_completes_mocked_ping_and_records_connectivity(tmp_path, monkeypatch) -> None:
    class FakeProcess:
        returncode = 0
        def poll(self):
            return 0
        def communicate(self, timeout=None):
            return ("4 packets transmitted, 4 received, 0% packet loss\nrtt min/avg/max/mdev = 1.0/2.0/3.0/0.1 ms\n", None)

    monkeypatch.setattr(jobs.subprocess, "Popen", lambda *args, **kwargs: FakeProcess())
    with InventoryStore(tmp_path / "inventory.db") as store:
        device_id = store.ingest(
            Observation("neighbor_table", "eth0", "192.168.1.20", "00:11:22:33:44:55", observed_at=100)
        )
        queued = store.queue_diagnostic(device_id, "192.168.1.20", "ping", now=200)
        claimed = store.claim_next_diagnostic(now=201)
        jobs.execute_job(store, claimed)
        completed = store.get_diagnostic_job(queued["id"])
        assert completed["status"] == "completed"
        assert "answered 4 of 4" in completed["result"]["summary"]
        assert store.get_device(device_id)["last_connectivity"] is not None


def test_scan_queue_is_local_bounded_and_deduplicated(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        first = store.queue_scan("192.168.1.0/24", "eth0", now=100)
        second = store.queue_scan("192.168.1.0/24", "eth0", now=101)
        assert first["id"] == second["id"]
        assert store.claim_next_scan(now=102)["status"] == "running"
        assert store.request_scan_cancel(first["id"], now=103)["cancel_requested"]
        assert store.scan_cancel_requested(first["id"])
        assert store.finish_scan(first["id"], "cancelled", now=104)["status"] == "cancelled"
        for network in ("8.8.8.0/24", "192.168.0.0/16"):
            try:
                store.queue_scan(network, "eth0")
            except ValueError:
                pass
            else:
                raise AssertionError("unsafe scan network should be rejected")


def test_worker_completes_mocked_discovery_without_offline_claims(tmp_path, monkeypatch) -> None:
    class FakeProcess:
        returncode = 0
        def poll(self):
            return 0
        def communicate(self, timeout=None):
            return ("Nmap scan report for 192.168.1.1\nNmap scan report for 192.168.1.20\n", None)

    monkeypatch.setattr(jobs.subprocess, "Popen", lambda *args, **kwargs: FakeProcess())
    monkeypatch.setattr(jobs.PassiveDiscoveryManager, "observe_once", lambda self: {"observations": 0, "errors": []})
    with InventoryStore(tmp_path / "inventory.db") as store:
        queued = store.queue_scan("192.168.1.0/24", "eth0", now=100)
        claimed = store.claim_next_scan(now=101)
        jobs.execute_scan(store, claimed)
        completed = store.get_scan_job(queued["id"])
        assert completed["status"] == "completed"
        assert completed["result"]["addresses"] == ["192.168.1.1", "192.168.1.20"]
        assert "may still be connected" in completed["result"]["summary"]


def test_scheduled_scans_require_all_authorization_gates() -> None:
    calls = []
    def runner(command, timeout):
        calls.append(command)
        if "route" in command:
            return 0, '[{"dev":"eth0"}]', ""
        return 0, '[{"addr_info":[{"family":"inet","scope":"global","local":"192.168.1.20"}]}]', ""

    disabled = CyberScoutConfig(
        active_discovery_enabled=False, scheduled_scan_minutes=60,
        approved_networks=("192.168.1.0/24",),
    )
    assert approved_local_scan_targets(disabled, runner) == []
    assert calls == []
    enabled = CyberScoutConfig(
        active_discovery_enabled=True, scheduled_scan_minutes=60,
        approved_networks=("192.168.1.0/24", "10.0.0.0/24"),
    )
    assert approved_local_scan_targets(enabled, runner) == [("eth0", "192.168.1.0/24")]


def test_configuration_rejects_type_confusion() -> None:
    for data in (
        {"active_discovery_enabled": 1},
        {"retention_days": True},
        {"approved_networks": "192.168.1.0/24"},
    ):
        try:
            CyberScoutConfig.from_mapping(data)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid configuration type should be rejected")


def test_dashboard_snapshot_uses_persisted_inventory(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        device_id = store.ingest(Observation(
            "neighbor_table", "eth0", "192.168.1.20", "00:11:22:33:44:55",
            state="REACHABLE", observed_at=1_000, active=True,
        ))
        store.update_device(device_id, recognition="recognized", occurred_at=1_001)
        snapshot = dashboard_snapshot(store, now=1_100, networks=["192.168.1.0/24"])
        assert snapshot["counts"] == {
            "total": 1, "recently_active": 1, "new_24h": 1, "unrecognized": 0,
        }
        assert snapshot["changes24h"]["device.first_observed"] == 1


def test_device_report_contains_only_persisted_evidence(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        device_id = store.ingest(Observation(
            "neighbor_table", "eth0", "192.168.1.20", "00:11:22:33:44:55",
            observed_at=1_000,
        ))
        store.record_services_for_address(
            "192.168.1.20", [{"protocol": "tcp", "port": 22, "service": "ssh"}],
            source="test_fixture", observed_at=1_010,
        )
        store.queue_diagnostic(device_id, "192.168.1.20", "ping", now=1_020)
        report = store.get_device_report(device_id)
        assert report["addresses"][0]["address"] == "192.168.1.20"
        assert report["services"][0]["port"] == 22
        assert report["services"][0]["source"] == "test_fixture"
        assert report["diagnostics"][0]["status"] == "queued"
        assert any(event["event_type"] == "device.service_added" for event in report["events"])


def test_keep_only_networks_removes_old_addresses_and_orphan_devices(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        retained = store.ingest(Observation(
            "neighbor_table", "eth0", "10.10.10.20", "00:11:22:33:44:55", observed_at=200,
        ))
        store.ingest(Observation(
            "neighbor_table", "wlan0", "192.168.1.20", "00:11:22:33:44:55", observed_at=100,
        ))
        removed = store.ingest(Observation(
            "neighbor_table", "wlan0", "192.168.1.30", "00:11:22:33:44:66", observed_at=100,
        ))
        result = store.keep_only_networks(["10.10.10.0/24", "10.24.27.0/24"])
        assert result["addresses"] == 2
        assert result["devices"] == 1
        assert store.get_device(retained)["addresses"][0]["address"] == "10.10.10.20"
        try:
            store.get_device(removed)
        except KeyError:
            pass
        else:
            raise AssertionError("device with only historical addresses should be removed")


def test_current_scope_follows_attached_private_interfaces() -> None:
    responses = {
        ("ip", "-j", "address", "show"): '[{"ifname":"eth0","flags":["UP"],"addr_info":[{"family":"inet","scope":"global","local":"10.2.3.4","prefixlen":24}]},{"ifname":"lo","flags":["UP"],"addr_info":[{"family":"inet","scope":"host","local":"127.0.0.1","prefixlen":8}]}]',
        ("ip", "-j", "route", "show", "default"): '[{"dev":"eth0","gateway":"10.2.3.1"}]',
    }
    scopes = current_ipv4_scopes(lambda command: responses[tuple(command)])
    assert scopes == [{
        "interface": "eth0", "address": "10.2.3.4",
        "network": "10.2.3.0/24", "gateway": "10.2.3.1",
    }]


def test_network_scoped_inventory_hides_previous_network(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        current = store.ingest(Observation("neighbor_table", "eth0", "10.2.3.20", "00:11:22:33:44:55"))
        store.ingest(Observation("neighbor_table", "wlan0", "192.168.9.20", "00:11:22:33:44:66"))
        visible = store.list_devices(networks=["10.2.3.0/24"])
        assert [item["id"] for item in visible] == [current]


def test_empty_current_scope_does_not_show_historical_devices(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        store.ingest(Observation("neighbor_table", "eth0", "10.2.3.20", "00:11:22:33:44:55"))
        assert store.list_devices(networks=[]) == []
        assert len(store.list_devices(networks=None)) == 1


def test_event_acknowledge_dismiss_and_restore(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        store.ingest(Observation(
            "neighbor_table", "eth0", "10.2.3.20", "00:11:22:33:44:55", observed_at=100,
        ))
        event_id = store.list_events()[0]["id"]
        acknowledged = store.set_event_state(event_id, "acknowledge", now=200)
        assert acknowledged["acknowledged_at"] == 200
        assert acknowledged["dismissed_at"] is None
        dismissed = store.set_event_state(event_id, "dismiss", now=300)
        assert dismissed["acknowledged_at"] is None
        assert dismissed["dismissed_at"] == 300
        restored = store.set_event_state(event_id, "restore", now=400)
        assert restored["acknowledged_at"] is None
        assert restored["dismissed_at"] is None


def test_dashboard_period_and_history_are_explicit(tmp_path) -> None:
    with InventoryStore(tmp_path / "inventory.db") as store:
        store.ingest(Observation(
            "neighbor_table", "eth0", "10.2.3.20", "00:11:22:33:44:55", observed_at=100,
        ))
        current = dashboard_snapshot(store, now=200, networks=[], period="7d")
        history = dashboard_snapshot(store, now=200, networks=[], period="7d", include_history=True)
        assert current["counts"]["total"] == 0
        assert history["counts"]["total"] == 1
        assert history["period"] == "7d"
