from datetime import datetime

packet = {
    "source_ip": "192.168.1.5",
    "destination_ip": "8.8.8.8",
    "protocol": "TCP",
    "source_port": 50000,
    "destination_port": 443,
    "packet_length": 64,
    "timestamp": datetime.now()
}

print(packet)