import scapy.all as scapy
from datetime import datetime, timedelta
import time
import sys
import logging
import signal
import threading
import platform
from interface_fetcher import get_active_interface

# Interface configuration (at top for easy change)
interface = get_active_interface() or "Intel(R) Wireless-AC 9560 160MHz"  # Dynamic fetch with hardcoded fallback

# Logging configuration
logging.basicConfig(level=logging.INFO)

# Time tracking for logging alerts
last_log_time = None
count = 1
sniffer = None
running = True

# Signal handler for graceful shutdown
def signal_handler(sig, frame):
    global sniffer, running
    logging.info("[+] Received SIGTERM, stopping detector...")
    running = False
    stop_sniffer()
    sys.exit(0)

# Register signal handler
signal.signal(signal.SIGTERM, signal_handler)

# Helper to stop sniffer safely
def stop_sniffer():
    global sniffer
    if sniffer and sniffer.running:
        try:
            sniffer.stop()
            logging.info("[+] Sniffer stopped successfully")
        except OSError as e:
            logging.warning(f"Caught OSError while stopping sniffer (likely Npcap issue): {e}")
        except Exception as e:
            logging.error(f"Error stopping sniffer: {e}")
        finally:
            sniffer = None  # Ensure sniffer is cleared

def get_mac(ip):
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        return answered_list[0][1].hwsrc if answered_list else None
    except Exception as e:
        logging.error(f"Error while getting MAC for IP {ip}: {e}")
        return None

def log_alert(src_ip, real_mac, spoofed_mac):
    global last_log_time, count
    current_time = datetime.utcnow()

    if count == 1:
        alert_data = {
            "timestamp": current_time,
            "type": "ARP Spoofing",
            "severity": "High",
            "status": "Unresolved",
            "description": f"Possible ARP Spoofing detected! Source IP: {src_ip}, Expected MAC: {real_mac}, Spoofed MAC: {spoofed_mac}",
            "sourceIP": src_ip,
            "destinationIP": None,
            "ports": [],
            "detectedBy": "ARP Detector",
            "recommendation": "Investigate the source IP for potential malicious activity.",
            "devicePriority": "High",
            "macAddress": real_mac,
            "deviceName": "",
        }

        logging.info("[+] Alert logged (no DB involved).")
        count = 0
        last_log_time = current_time
    else:
        logging.info("[+] Alert already logged, suppressing further alerts for 20 minutes.")
        time.sleep(1200)  # 20 minutes in seconds

def process_sniffed_packet(packet):
    try:
        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc

            if real_mac and real_mac != response_mac:
                if count == 1:
                    print("[+] You are Under Attack...!!!!!")
                    print(f"    [Expected MAC] {real_mac}  |  [Spoofed MAC] {response_mac}")
                log_alert(packet[scapy.ARP].psrc, real_mac, response_mac)
    except Exception as e:
        logging.error(f"Error processing packet: {e}")

def start_sniffing(interface):
    global sniffer, running
    try:
        sniffer = scapy.AsyncSniffer(iface=interface, store=False, prn=process_sniffed_packet)
        sniffer.start()
        logging.info("[+] Running Detector ..")
        while running:
            time.sleep(1)  # Keep thread alive, checking running flag
    except Exception as e:
        logging.error(f"Error during sniffing: {e}")
        sys.exit(1)
    finally:
        stop_sniffer()  # Ensure sniffer stops even on exception

def reset_count():
    global count, last_log_time
    while running:
        current_time = datetime.utcnow()
        if last_log_time and current_time - last_log_time >= timedelta(minutes=20):
            count = 1
            logging.info("[+] 20 minutes passed. Count reset to 1.")
            last_log_time = current_time
        time.sleep(60)

if __name__ == "__main__":
    try:
        if platform.system() == "Windows":
            scapy.conf.use_pcap = True  # Use Npcap on Windows for better compatibility

        if not interface:
            logging.error("Failed to find a valid interface")
            sys.exit(1)

        sniff_thread = threading.Thread(target=start_sniffing, args=(interface,), daemon=True)
        sniff_thread.start()

        threading.Thread(target=reset_count, daemon=True).start()

        # Main loop to keep script alive until interrupted
        while running:
            time.sleep(1)

    except KeyboardInterrupt:
        logging.info("[+] Detector stopped by user")
        running = False
        stop_sniffer()
        sys.exit(0)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        running = False
        stop_sniffer()
        sys.exit(1)
