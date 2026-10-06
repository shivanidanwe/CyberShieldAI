from datetime import datetime, timedelta

SUSPICIOUS_PORTS = {
    21: {"attack": "FTP Access", "severity": "MEDIUM"},
    23: {"attack": "Telnet Access", "severity": "HIGH"},
    22: {"attack": "SSH Access", "severity": "LOW"},
    3389: {"attack": "Remote Desktop", "severity": "HIGH"},
    445: {"attack": "SMB Access", "severity": "MEDIUM"},
}

# Default lookup when render_scan works purely off stored records.
SCAN_WINDOW_SECONDS = 60
SCAN_DISTINCT_PORTS = 8


def build_packet_rule(packet):
    if not packet:
        return None

    destination_port = packet.get("destination_port")
    packet_length = packet.get("packet_length", 0)
    protocol = packet.get("protocol", "").upper()

    if destination_port in SUSPICIOUS_PORTS:
        rule = SUSPICIOUS_PORTS[destination_port]
        return {
            "source_ip": packet.get("source_ip"),
            "destination_ip": packet.get("destination_ip"),
            "attack_type": rule["attack"],
            "severity": rule["severity"],
            "description": f"Traffic matched a suspicious service on port {destination_port}.",
        }

    if protocol == "ICMP" and packet_length > 800:
        return {
            "source_ip": packet.get("source_ip"),
            "destination_ip": packet.get("destination_ip"),
            "attack_type": "ICMP Flood",
            "severity": "HIGH",
            "description": "ICMP traffic exceeded the configured packet-size threshold for abnormal activity.",
        }

    if packet_length > 1500:
        return {
            "source_ip": packet.get("source_ip"),
            "destination_ip": packet.get("destination_ip"),
            "attack_type": "Large Packet",
            "severity": "MEDIUM",
            "description": "An unusually large packet size suggests probing or payload transfer behavior.",
        }

    return None


def detect_port_scan(packets, window_seconds: int = SCAN_WINDOW_SECONDS, threshold: int = SCAN_DISTINCT_PORTS):
    """Correlate a recent set of packets into a port-scan alert.

    ``packets`` is an iterable of dicts with ``source_ip``, ``destination_ip``,
    ``destination_port`` and ``timestamp``. Returns one alert dict per source
    that contacted at least ``threshold`` distinct destination ports inside a
    single ``window_seconds`` window.
    """
    grouped: dict[str, list] = {}
    for packet in packets:
        source = packet.get("source_ip")
        if not source:
            continue
        timestamp = packet.get("timestamp")
        if timestamp is None:
            timestamp = datetime.utcnow()
        grouped.setdefault(source, []).append(
            {
                "destination_port": packet.get("destination_port"),
                "destination_ip": packet.get("destination_ip"),
                "timestamp": timestamp,
            }
        )

    alerts = []
    for source, history in grouped.items():
        history = sorted(history, key=lambda item: item["timestamp"] if item["timestamp"] else datetime.min)
        window_start = 0
        for index, item in enumerate(history):
            current_time = item["timestamp"] if item["timestamp"] else datetime.utcnow()
            while (
                window_start < index
                and history[window_start]["timestamp"]
                and current_time - history[window_start]["timestamp"] > timedelta(seconds=window_seconds)
            ):
                window_start += 1

            window = history[window_start : index + 1]
            distinct_ports = {entry["destination_port"] for entry in window if entry["destination_port"] is not None}
            if len(distinct_ports) >= threshold:
                target = max({entry["destination_ip"] for entry in window if entry["destination_ip"]}, default="unknown")
                alerts.append(
                    {
                        "source_ip": source,
                        "destination_ip": target,
                        "attack_type": "Port Scan",
                        "severity": "MEDIUM",
                        "description": (
                            f"{source} contacted {len(distinct_ports)} distinct destination ports "
                            f"within {window_seconds}s — possible reconnaissance."
                        ),
                    }
                )
                break

    return alerts