"""CyberShield AI — Deep Packet Parser (Wireshark-style).

Extracts comprehensive protocol-layer metadata from raw Scapy packets,
going far beyond basic IP headers to capture TCP flags, DNS queries,
HTTP methods/hosts, ICMP types, TLS versions, TTL, and payload previews.
"""

from datetime import datetime

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import Ether
from scapy.packet import Raw

PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

# Well-known port -> application-layer service name
SERVICE_MAP = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 587: "SMTP", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5060: "SIP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

# TCP flag bit-names
TCP_FLAGS = {
    0x01: "FIN", 0x02: "SYN", 0x04: "RST", 0x08: "PSH",
    0x10: "ACK", 0x20: "URG", 0x40: "ECE", 0x80: "CWR",
}


def _flags_to_str(flags_int):
    """Convert TCP flags integer to readable string like 'SYN ACK'."""
    parts = []
    for bit, name in TCP_FLAGS.items():
        if flags_int & bit:
            parts.append(name)
    return " ".join(parts) if parts else ""


def _detect_service(src_port, dst_port):
    """Identify application-layer service from well-known port numbers."""
    if dst_port in SERVICE_MAP:
        return SERVICE_MAP[dst_port]
    if src_port in SERVICE_MAP:
        return SERVICE_MAP[src_port]
    return None


def _extract_payload_preview(packet, max_bytes=64):
    """Extract a short hex + ASCII payload preview like Wireshark."""
    if packet.haslayer(Raw):
        raw = bytes(packet[Raw].load[:max_bytes])
        hex_str = raw.hex()
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
        return {"hex": hex_str, "ascii": ascii_str, "length": len(packet[Raw].load)}
    return None


def _extract_dns_info(packet):
    """Extract DNS query/response details."""
    if not packet.haslayer(DNS):
        return None
    dns = packet[DNS]
    info = {"id": dns.id, "is_response": bool(dns.qr)}
    if dns.qdcount and packet.haslayer(DNSQR):
        qname = packet[DNSQR].qname
        if isinstance(qname, bytes):
            qname = qname.decode("utf-8", errors="replace").rstrip(".")
        info["query_name"] = qname
        info["query_type"] = packet[DNSQR].sprintf("%DNSQR.qtype%")
    return info


def _extract_http_info(packet):
    """Detect and extract HTTP request/response lines from payload."""
    if not packet.haslayer(Raw):
        return None
    try:
        data = bytes(packet[Raw].load[:512])
        text = data.decode("utf-8", errors="replace")
        first_line = text.split("\r\n")[0] if "\r\n" in text else text.split("\n")[0]

        # HTTP Request: GET /path HTTP/1.1
        http_methods = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")
        for method in http_methods:
            if first_line.startswith(method + " "):
                parts = first_line.split(" ")
                info = {"type": "request", "method": parts[0], "uri": parts[1] if len(parts) > 1 else "/"}
                # Try to find Host header
                for line in text.split("\r\n"):
                    if line.lower().startswith("host:"):
                        info["host"] = line.split(":", 1)[1].strip()
                        break
                return info

        # HTTP Response: HTTP/1.1 200 OK
        if first_line.startswith("HTTP/"):
            parts = first_line.split(" ", 2)
            return {
                "type": "response",
                "version": parts[0],
                "status_code": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None,
                "reason": parts[2] if len(parts) > 2 else None,
            }
    except Exception:
        pass
    return None


def _build_layers(packet):
    """Build a Wireshark-style protocol layer list."""
    layers = []

    # Layer 2: Ethernet
    if packet.haslayer(Ether):
        eth = packet[Ether]
        layers.append({
            "name": "Ethernet II",
            "fields": {
                "Source MAC": eth.src,
                "Destination MAC": eth.dst,
                "EtherType": hex(eth.type),
            }
        })

    # Layer 3: IP
    if packet.haslayer(IP):
        ip = packet[IP]
        layers.append({
            "name": "Internet Protocol v4",
            "fields": {
                "Source": ip.src,
                "Destination": ip.dst,
                "Version": ip.version,
                "Header Length": f"{ip.ihl * 4} bytes",
                "TTL": ip.ttl,
                "Protocol": PROTOCOL_MAP.get(ip.proto, str(ip.proto)),
                "Total Length": ip.len,
                "Identification": hex(ip.id),
                "Flags": str(ip.flags),
                "Fragment Offset": ip.frag,
            }
        })

    # Layer 4: TCP
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        flags_str = _flags_to_str(int(tcp.flags))
        layers.append({
            "name": "Transmission Control Protocol",
            "fields": {
                "Source Port": tcp.sport,
                "Destination Port": tcp.dport,
                "Sequence Number": tcp.seq,
                "Acknowledgment Number": tcp.ack,
                "Flags": flags_str,
                "Window Size": tcp.window,
                "Checksum": hex(tcp.chksum) if tcp.chksum else "N/A",
            }
        })

    # Layer 4: UDP
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        layers.append({
            "name": "User Datagram Protocol",
            "fields": {
                "Source Port": udp.sport,
                "Destination Port": udp.dport,
                "Length": udp.len,
                "Checksum": hex(udp.chksum) if udp.chksum else "N/A",
            }
        })

    # Layer 4: ICMP
    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        type_names = {0: "Echo Reply", 3: "Destination Unreachable", 5: "Redirect",
                      8: "Echo Request", 11: "Time Exceeded"}
        layers.append({
            "name": "Internet Control Message Protocol",
            "fields": {
                "Type": f"{icmp.type} ({type_names.get(icmp.type, 'Other')})",
                "Code": icmp.code,
                "Checksum": hex(icmp.chksum) if icmp.chksum else "N/A",
                "ID": icmp.id if hasattr(icmp, "id") else "N/A",
                "Sequence": icmp.seq if hasattr(icmp, "seq") else "N/A",
            }
        })

    # Layer 7: DNS
    if packet.haslayer(DNS):
        dns_info = _extract_dns_info(packet)
        if dns_info:
            layers.append({
                "name": "Domain Name System",
                "fields": {k: str(v) for k, v in dns_info.items()}
            })

    # Payload
    if packet.haslayer(Raw):
        payload = _extract_payload_preview(packet)
        if payload:
            layers.append({
                "name": f"Data ({payload['length']} bytes)",
                "fields": {
                    "Payload (hex)": payload["hex"][:128],
                    "Payload (ASCII)": payload["ascii"][:64],
                }
            })

    return layers


def parse_packet(packet):
    """Parse a raw Scapy packet into a rich metadata dictionary.

    Returns basic fields for database storage plus deep-inspection
    metadata for Wireshark-style protocol analysis.
    """
    if not packet or not packet.haslayer(IP):
        return None

    ip = packet[IP]
    src_port = None
    dst_port = None
    tcp_flags = None
    ttl = ip.ttl

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        src_port = tcp.sport
        dst_port = tcp.dport
        tcp_flags = _flags_to_str(int(tcp.flags))
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        src_port = udp.sport
        dst_port = udp.dport
    elif packet.haslayer(ICMP):
        src_port = None
        dst_port = None

    protocol = PROTOCOL_MAP.get(ip.proto, str(ip.proto))
    service = _detect_service(src_port, dst_port)

    # Application-layer deep inspection
    dns_info = _extract_dns_info(packet)
    http_info = _extract_http_info(packet)
    payload = _extract_payload_preview(packet)

    # Build Wireshark-style summary "info" column
    info = _build_info_summary(protocol, tcp_flags, src_port, dst_port, service, dns_info, http_info, packet)

    data = {
        # Core fields (stored in DB)
        "source_ip": ip.src,
        "destination_ip": ip.dst,
        "protocol": protocol,
        "source_port": src_port,
        "destination_port": dst_port,
        "packet_length": len(packet),
        "timestamp": datetime.utcnow(),

        # Deep inspection fields (returned via API, stored in info column)
        "ttl": ttl,
        "tcp_flags": tcp_flags,
        "service": service,
        "info": info,
        "dns_info": dns_info,
        "http_info": http_info,
        "payload_preview": payload,
        "layers": _build_layers(packet),
    }

    return data


def _build_info_summary(protocol, tcp_flags, src_port, dst_port, service, dns_info, http_info, packet):
    """Generate a concise Wireshark-style 'Info' column summary."""
    parts = []

    if http_info:
        if http_info.get("type") == "request":
            parts.append(f"{http_info['method']} {http_info.get('uri', '/')}")
            if http_info.get("host"):
                parts.append(f"Host: {http_info['host']}")
        elif http_info.get("type") == "response":
            parts.append(f"{http_info.get('version', 'HTTP')} {http_info.get('status_code', '')} {http_info.get('reason', '')}")
        return " | ".join(parts)

    if dns_info:
        qtype = dns_info.get("query_type", "")
        qname = dns_info.get("query_name", "")
        direction = "Response" if dns_info.get("is_response") else "Query"
        return f"DNS {direction}: {qtype} {qname}".strip()

    if protocol == "TCP" and tcp_flags:
        port_info = f"{src_port} -> {dst_port}" if src_port and dst_port else ""
        svc = f" [{service}]" if service else ""
        return f"{port_info}{svc} [{tcp_flags}]"

    if protocol == "UDP":
        port_info = f"{src_port} -> {dst_port}" if src_port and dst_port else ""
        svc = f" [{service}]" if service else ""
        return f"{port_info}{svc}"

    if protocol == "ICMP":
        if packet.haslayer(ICMP):
            icmp = packet[ICMP]
            type_names = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable", 11: "TTL Exceeded"}
            return type_names.get(icmp.type, f"Type {icmp.type}")

    return service or ""