from app.detection.rules import SUSPICIOUS_PORTS


def detect(packet):

    port = packet["destination_port"]

    if port in SUSPICIOUS_PORTS:

        rule = SUSPICIOUS_PORTS[port]

        return {

            "source_ip": packet["source_ip"],

            "destination_ip": packet["destination_ip"],

            "attack_type": rule["attack"],

            "severity": rule["severity"],

            "description": f"Traffic detected on suspicious port {port}"

        }

    return None