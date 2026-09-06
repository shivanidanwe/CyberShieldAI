from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime

protocol_map = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}

def parse_packet(packet):

    if not packet.haslayer(IP):
        return None

    ip = packet[IP]

    data = {
        "source_ip": ip.src,
        "destination_ip": ip.dst,
        "protocol": protocol_map.get(ip.proto, str(ip.proto)),
        "source_port": None,
        "destination_port": None,
        "packet_length": len(packet),
        "timestamp": datetime.now()
    }

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        data["source_port"] = tcp.sport
        data["destination_port"] = tcp.dport

    elif packet.haslayer(UDP):
        udp = packet[UDP]
        data["source_port"] = udp.sport
        data["destination_port"] = udp.dport

    return data