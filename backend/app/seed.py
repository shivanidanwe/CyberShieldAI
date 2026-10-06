"""Demo-data seeding for CyberShield AI.

Generates a realistic 7-day corpus of packets and alerts so the dashboard and
AI features have something meaningful to show on first run.

Usage:
    python -m app.seed            # seed only if the tables are empty
    python -m app.seed --force    # reseed even if data exists
    python -m app.seed --clear    # wipe all packets/alerts first, then reseed

Behaviour at startup is controlled by the AUTO_SEED env var (default "1");
seeding only happens when the database is empty.
"""

from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta

from app.database import SessionLocal
from app.models import Alert, Packet

MODE_LABELS = {
    "primary": {"dest": "10.0.0.10", "attack": "Telnet Access", "severity": "HIGH"},
    "ftp": {"dest": "10.0.0.21", "attack": "FTP Access", "severity": "MEDIUM"},
    "ssh": {"dest": "10.0.0.22", "attack": "SSH Access", "severity": "LOW"},
    "rdp": {"dest": "10.0.0.50", "attack": "Remote Desktop", "severity": "HIGH"},
    "smb": {"dest": "10.0.0.45", "attack": "SMB Access", "severity": "MEDIUM"},
    "icmp": {"dest": "10.0.0.8", "attack": "ICMP Flood", "severity": "HIGH"},
    "large": {"dest": "10.0.0.30", "attack": "Large Packet", "severity": "MEDIUM"},
    "scan": {"dest": "10.0.0.99", "attack": "Port Scan", "severity": "MEDIUM"},
}

_SOURCES = ["192.168.1.15", "192.168.1.22", "192.168.1.31", "172.16.5.10", "172.16.9.4", "10.0.0.3", "203.0.113.7"]
_CLEAN_SOURCES = ["10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"]

_PROTOCOLS = ["TCP", "TCP", "TCP", "UDP", "UDP", "ICMP"]

# mode -> (protocol, destination_port, length_range)
_MODE_PROFILES = {
    "primary": ("TCP", 23, (300, 600)),
    "ftp": ("TCP", 21, (200, 500)),
    "ssh": ("TCP", 22, (200, 500)),
    "rdp": ("TCP", 3389, (400, 900)),
    "smb": ("TCP", 445, (600, 1200)),
    "icmp": ("ICMP", None, (900, 1500)),
    "large": ("TCP", None, (1501, 2100)),
    "scan": ("TCP", None, (60, 180)),
}

_SAFE_PORTS = [80, 443, 53]


def _stamp(days_back: int, rng: random.Random) -> datetime:
    return datetime.utcnow() - timedelta(
        days=days_back,
        hours=rng.randint(0, 23),
        minutes=rng.randint(0, 59),
        seconds=rng.randint(0, 59),
    )


def seed(force: bool = False, clear: bool = False) -> int:
    db = SessionLocal()
    try:
        existing = db.query(Packet).count() + db.query(Alert).count()
        if existing and not force:
            return 0

        if clear:
            db.query(Alert).delete()
            db.query(Packet).delete()
            db.commit()

        rng = random.Random(2026)
        packets: list[dict] = []

        # 1: background — every clean host, every day
        for day in range(6, -1, -1):
            for source in _CLEAN_SOURCES:
                protocol = rng.choice(["TCP", "UDP"])
                port = rng.choice(_SAFE_PORTS)
                packets.append(
                    {
                        "source_ip": source,
                        "destination_ip": "10.0.0.254",
                        "protocol": protocol,
                        "source_port": rng.randint(10000, 60000),
                        "destination_port": port if protocol == "TCP" else None,
                        "packet_length": rng.randint(48, 512),
                        "timestamp": _stamp(day, rng),
                        "mode": None,
                    }
                )

        # 2: suspicious bursts across the week
        for index, mode in enumerate(MODE_LABELS):
            source = _SOURCES[index % len(_SOURCES)]
            day = rng.randint(0, 6)
            protocol, fixed_port, length_range = _MODE_PROFILES[mode]
            for _ in range(rng.randint(3, 6)):
                packets.append(
                    {
                        "source_ip": source,
                        "destination_ip": MODE_LABELS[mode]["dest"],
                        "protocol": protocol,
                        "source_port": rng.randint(1024, 60000),
                        "destination_port": fixed_port if fixed_port is not None else rng.choice([80, 443, 8080]),
                        "packet_length": rng.randint(*length_range),
                        "timestamp": _stamp(day, rng),
                        "mode": mode,
                    }
                )

        # 3: port-scan sweep — one source, many ports, under a minute
        scan_source = _SOURCES[6]
        sweep_start = datetime.utcnow() - timedelta(hours=3)
        for port in range(21, 40):
            packets.append(
                {
                    "source_ip": scan_source,
                    "destination_ip": "10.0.0.99",
                    "protocol": "TCP",
                    "source_port": rng.randint(1024, 65535),
                    "destination_port": port,
                    "packet_length": rng.randint(40, 120),
                    "timestamp": sweep_start + timedelta(seconds=port),
                    "mode": None,
                }
            )

        # persist packets
        for pkt in packets:
            db.add(
                Packet(
                    source_ip=pkt["source_ip"],
                    destination_ip=pkt["destination_ip"],
                    protocol=pkt["protocol"],
                    source_port=pkt["source_port"],
                    destination_port=pkt["destination_port"],
                    packet_length=pkt["packet_length"],
                    timestamp=pkt["timestamp"],
                )
            )
        db.flush()  # assign ids and let any integrity error surface before alerts
        packet_count = len(packets)

        # alerts from suspicious bursts
        alerts = []
        for pkt in packets:
            if not pkt.get("mode"):
                continue
            mode = pkt["mode"]
            tpl = MODE_LABELS[mode]
            profile = _MODE_PROFILES[mode]
            port = profile[1]
            description = (
                f"Traffic matched a suspicious service on port {port}."
                if port is not None
                else (
                    "ICMP traffic exceeded the configured packet-size threshold for abnormal activity."
                    if mode == "icmp"
                    else "An unusually large packet size suggests probing or payload transfer behavior."
                )
            )
            alerts.append(
                Alert(
                    source_ip=pkt["source_ip"],
                    destination_ip=pkt["destination_ip"],
                    attack_type=tpl["attack"],
                    severity=tpl["severity"],
                    description=description,
                    timestamp=pkt["timestamp"],
                )
            )

        # port-scan alert from the sweep burst
        alerts.append(
            Alert(
                source_ip=scan_source,
                destination_ip="10.0.0.99",
                attack_type="Port Scan",
                severity="MEDIUM",
                description=f"{scan_source} contacted 18 distinct destination ports within 60s.",
                timestamp=sweep_start,
            )
        )

        db.add_all(alerts)
        db.commit()
        return packet_count + len(alerts)
    finally:
        db.close()


def maybe_seed() -> None:
    """Seed automatically on startup when the tables are empty (AUTO_SEED=1)."""
    import os

    if os.getenv("AUTO_SEED", "1") != "1":
        return
    created = seed(force=False)
    if created:
        from app.utils.logger import get_logger

        get_logger("seed").info("Seeded demo dataset: %s records created.", created)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed demo data for CyberShield AI")
    parser.add_argument("--force", action="store_true", help="Reseed even if data exists")
    parser.add_argument("--clear", action="store_true", help="Delete existing packets/alerts first")
    args = parser.parse_args()

    created = seed(force=args.force, clear=args.clear)
    print(f"Seeding complete — {created} records created." if created else "No seeding needed (data already present).")