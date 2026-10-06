import logging
import socket
import threading

from scapy.all import IFACES, sniff
from scapy.config import conf

if hasattr(conf, "use_pcap"):
    conf.use_pcap = True
if hasattr(conf, "use_npcap"):
    conf.use_npcap = True

from app.database import SessionLocal
from app.detection.detection_engine import detect
from app.packet_capture.packet_parser import parse_packet
from app.services.alert_service import AlertService
from app.services.packet_service import PacketService

_capture_lock = threading.RLock()
_capture_thread = None
_capture_stop_event = None
_capture_interface = None


def get_best_interface():
    """Auto-detect the most active, routable network interface on Windows/Linux."""
    # 1. Determine outbound local IP via UDP socket connection check
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        for iface in IFACES.values():
            if getattr(iface, "ip", None) == local_ip:
                return iface
    except Exception as exc:
        logging.debug("Could not resolve outbound IP via socket: %s", exc)

    # 2. Look for any interface with a non-loopback, non-APIPA IPv4 address
    try:
        for iface in IFACES.values():
            ip = getattr(iface, "ip", "")
            if ip and not ip.startswith("127.") and not ip.startswith("169.254."):
                return iface
    except Exception:
        pass

    return conf.iface


def _process_packet(packet):
    parsed = parse_packet(packet)
    if not parsed:
        return

    db = SessionLocal()
    try:
        PacketService.save_packet(db, parsed)
        src_pt = parsed.get("source_port") or "*"
        dst_pt = parsed.get("destination_port") or "*"
        print(f"[PACKET] {parsed['protocol']:<4} {parsed['source_ip']}:{src_pt} -> {parsed['destination_ip']}:{dst_pt} ({parsed['packet_length']}B)")
        alert = detect(parsed)
        if alert:
            AlertService.create_alert(db, alert)
            print(f"  >>> [ALERT TRIGGERED] {alert['attack_type']} [{alert['severity']}] - {alert['description']}")
            logging.info("ALERT: %s (%s)", alert["attack_type"], alert["severity"])
    except Exception:
        logging.exception("Failed to process captured packet")
    finally:
        db.close()



def get_capture_status():
    with _capture_lock:
        active = _capture_thread is not None and _capture_thread.is_alive()
        return {
            "enabled": active,
            "status": "running" if active else "stopped",
            "interface": _capture_interface or "auto",
        }


def start_capture(count: int = 0, iface=None):
    global _capture_thread, _capture_stop_event, _capture_interface

    with _capture_lock:
        if _capture_thread is not None and _capture_thread.is_alive():
            return get_capture_status()
        _capture_stop_event = threading.Event()
        target_iface = iface or get_best_interface()
        desc = getattr(target_iface, "description", getattr(target_iface, "name", str(target_iface)))
        ip = getattr(target_iface, "ip", "")
        _capture_interface = f"{desc} ({ip})" if ip else desc

    def _capture_loop():
        global _capture_interface
        logging.info("Starting packet capture loop on %s", _capture_interface)
        try:
            while not _capture_stop_event.is_set():
                sniff(
                    prn=_process_packet,
                    store=False,
                    count=count if count > 0 else 0,
                    iface=target_iface,
                    timeout=1.0,
                )
                if count > 0:
                    break
        except Exception as e:
            logging.warning("Live capture failed on %s: %s. Falling back to simulation mode...", _capture_interface, e)
            import random
            import time
            from datetime import datetime, timezone

            while not _capture_stop_event.is_set():
                sim_proto = random.choice(["TCP", "UDP", "ICMP"])
                sim_src_port = random.randint(1024, 65535) if sim_proto != "ICMP" else None
                sim_dst_port = random.choice([80, 443, 22, 53, 3306]) if sim_proto != "ICMP" else None

                sim_packet = {
                    "source_ip": f"192.168.1.{random.randint(10, 50)}",
                    "destination_ip": f"10.0.0.{random.randint(1, 200)}",
                    "protocol": sim_proto,
                    "source_port": sim_src_port,
                    "destination_port": sim_dst_port,
                    "packet_length": random.randint(40, 1500),
                    "timestamp": datetime.now(timezone.utc),
                    "ttl": random.randint(50, 128),
                    "service": "Simulated",
                    "info": f"Simulated {sim_proto} packet",
                }

                # 5% chance to simulate a suspicious packet (e.g., Telnet)
                if random.random() < 0.05 and sim_proto == "TCP":
                    sim_packet["destination_port"] = 23
                    sim_packet["service"] = "Telnet"
                    sim_packet["info"] = "Telnet connection attempt (port 23)"

                db = SessionLocal()
                try:
                    PacketService.save_packet(db, sim_packet)
                    alert = detect(sim_packet)
                    if alert:
                        AlertService.create_alert(db, alert)
                        print(f"  >>> [SIM-ALERT TRIGGERED] {alert['attack_type']} [{alert['severity']}]")
                except Exception as ex:
                    logging.exception(f"Sim packet error: {ex}")
                finally:
                    db.close()

                time.sleep(random.uniform(0.5, 1.5))
        finally:
            with _capture_lock:
                _capture_thread = None

    try:
        _capture_thread = threading.Thread(target=_capture_loop, daemon=True, name="cybershield-capture")
        _capture_thread.start()
        return get_capture_status()
    except Exception:
        with _capture_lock:
            _capture_thread = None
        raise


def stop_capture():
    global _capture_thread, _capture_stop_event, _capture_interface

    with _capture_lock:
        if _capture_thread is None or not _capture_thread.is_alive():
            return get_capture_status()
        if _capture_stop_event is not None:
            _capture_stop_event.set()
        current_thread = _capture_thread

    current_thread.join(timeout=2.5)

    with _capture_lock:
        _capture_thread = None
        _capture_stop_event = None

    return get_capture_status()


if __name__ == "__main__":
    print("=" * 65)
    print("[+] CyberShield AI - Live Packet Sniffer")
    print("=" * 65)
    print("Listening for network traffic on authorized interfaces...")
    print("Press Ctrl+C to terminate capture.\n")
    try:
        sniff(prn=_process_packet, store=False)
    except KeyboardInterrupt:
        print("\n[+] Packet capture stopped by user.")
    except Exception as exc:
        print(f"\n[-] Capture failed: {exc}")
        print("Note: On Windows, Scapy live sniffing requires Npcap (https://npcap.com/) installed")
        print("and administrator privileges. You can also inject synthetic packets with test_packet.py.")