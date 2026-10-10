"""Loopback-only, read-only Cyber Scout dashboard."""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import time
from urllib.parse import parse_qs, urlsplit

from .database import DEFAULT_DATABASE, InventoryStore
from .scope import current_ipv4_scopes

HOST = "127.0.0.1"
PORT = 8765
ASSET = Path(__file__).with_name("dashboard.html")


def dashboard_snapshot(store: InventoryStore, now: int | None = None, networks: list[str] | None = None) -> dict:
    timestamp = int(now if now is not None else time.time())
    active_networks = networks if networks is not None else [item["network"] for item in current_ipv4_scopes()]
    visible_ids = {item["id"] for item in store.list_devices(networks=active_networks, limit=1000)}
    changes: dict[str, int] = {}
    for event in store.list_events(since=timestamp - 86400, until=timestamp, limit=1000):
        if event.get("device_id") not in visible_ids:
            continue
        changes[event["event_type"]] = changes.get(event["event_type"], 0) + 1
    return {
        "generatedAt": timestamp,
        "networks": active_networks,
        "counts": store.counts_for_networks(active_networks, timestamp),
        "changes24h": changes,
    }


def _device_rows(store: InventoryStore, query: dict[str, list[str]], networks: list[str]) -> list[dict]:
    devices = store.list_devices(
        search=query.get("search", [""])[0],
        recognition=query.get("recognition", [None])[0],
        category=query.get("category", [None])[0],
        limit=int(query.get("limit", ["250"])[0]),
        networks=networks,
    )
    for device in devices:
        details = store.get_device(device["id"])
        device["addresses"] = details["addresses"]
        device["hostnames"] = details["hostnames"]
    return devices


def make_handler(database: Path | str = DEFAULT_DATABASE) -> type[BaseHTTPRequestHandler]:
    class DashboardHandler(BaseHTTPRequestHandler):
        server_version = "CyberScout/1"

        def _headers(self, status: int, content_type: str, *, length: int | None = None,
                     download: str | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
            if length is not None:
                self.send_header("Content-Length", str(length))
            if download:
                self.send_header("Content-Disposition", f'attachment; filename="{download}"')
            self.end_headers()

        def _json(self, value: object, status: int = 200, *, download: str | None = None) -> None:
            body = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
            self._headers(status, "application/json; charset=utf-8", length=len(body), download=download)
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
            request = urlsplit(self.path)
            try:
                if request.path in {"/", "/index.html"}:
                    body = ASSET.read_bytes()
                    self._headers(200, "text/html; charset=utf-8", length=len(body))
                    self.wfile.write(body)
                    return
                if request.path == "/dashboard.js":
                    body = ASSET.with_name("dashboard.js").read_bytes()
                    self._headers(200, "text/javascript; charset=utf-8", length=len(body))
                    self.wfile.write(body)
                    return
                with InventoryStore(database) as store:
                    networks = [item["network"] for item in current_ipv4_scopes()]
                    if request.path == "/api/overview":
                        self._json(dashboard_snapshot(store, networks=networks))
                        return
                    if request.path == "/api/devices":
                        self._json({"networks": networks, "devices": _device_rows(store, parse_qs(request.query), networks)})
                        return
                    if request.path == "/api/events":
                        query = parse_qs(request.query)
                        since = int(query.get("since", [str(int(time.time()) - 604800)])[0])
                        visible_ids = {item["id"] for item in store.list_devices(networks=networks, limit=1000)}
                        events = [item for item in store.list_events(since=since, limit=1000)
                                  if item.get("device_id") in visible_ids]
                        self._json({"networks": networks, "events": events[:250]})
                        return
                    if request.path.startswith("/api/devices/"):
                        device_id = request.path.removeprefix("/api/devices/")
                        if not device_id or "/" in device_id or len(device_id) > 64:
                            raise ValueError("Invalid device ID")
                        report = store.get_device_report(device_id)
                        visible_ids = {item["id"] for item in store.list_devices(networks=networks, limit=1000)}
                        if device_id not in visible_ids:
                            raise KeyError("Device is not on a currently attached network")
                        if query := parse_qs(request.query):
                            if query.get("download") == ["1"]:
                                self._json(report, download=f"cyber-scout-device-{device_id}.json")
                                return
                        self._json({"device": report})
                        return
                    if request.path == "/api/export":
                        visible = store.list_devices(networks=networks, limit=1000)
                        devices = [store.get_device_report(item["id"]) for item in visible]
                        self._json(
                            {"exportedAt": int(time.time()), "networks": networks,
                             "counts": store.counts_for_networks(networks), "devices": devices},
                            download="cyber-scout-inventory.json",
                        )
                        return
                self._json({"error": "Not found"}, 404)
            except (KeyError, OSError, ValueError) as error:
                self._json({"error": str(error)}, 400)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    return DashboardHandler


def main() -> int:
    parser = argparse.ArgumentParser(description="Cyber Scout loopback dashboard")
    parser.add_argument("--host", default=HOST, choices=[HOST, "::1"])
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    server = ThreadingHTTPServer((args.host, args.port), make_handler())
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
