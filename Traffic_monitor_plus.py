import json
import logging
import subprocess
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
from scapy.all import ARP, sniff
import scapy.all as scapy
from mac_vendor_lookup import MacLookup, VendorNotFoundError
from logging.handlers import RotatingFileHandler
import smtplib
from email.mime.text import MIMEText
from collections import defaultdict
import time
import datetime

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Configure file logging
log_file_handler = RotatingFileHandler("network_monitor.log", maxBytes=5*1024*1024, backupCount=2)
log_file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logging.getLogger().addHandler(log_file_handler)

# Email alert configuration
EMAIL_ALERTS_ENABLED = True
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587
EMAIL_USERNAME = "your_email@example.com"
EMAIL_PASSWORD = "your_password"
ALERT_RECIPIENT = "admin@example.com"

def send_email_alert(subject, message):
    """Sends an email alert for critical events."""
    if not EMAIL_ALERTS_ENABLED:
        return

    try:
        msg = MIMEText(message)
        msg["Subject"] = subject
        msg["From"] = EMAIL_USERNAME
        msg["To"] = ALERT_RECIPIENT

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
            server.sendmail(EMAIL_USERNAME, ALERT_RECIPIENT, msg.as_string())
        logging.info(f"[INFO] Email alert sent to {ALERT_RECIPIENT}.")
    except Exception as e:
        logging.error(f"[ERROR] Failed to send email alert. Error: {e}")

# Store known MAC addresses and a blacklist
known_devices = set()
blacklisted_devices = {}

# Initialize the MAC lookup object
logging.info("[*] Initializing MAC Vendor Lookup...")
try:
    mac_lookup = MacLookup()
    logging.info("[+] MAC Vendor Lookup initialized.")
except Exception as e:
    logging.warning(f"[WARN] Could not initialize MAC Vendor Lookup. Vendor info might be unavailable. Error: {e}")
    mac_lookup = None

def disconnect_device(mac, interface="eth0"):
    """Sends deauthentication packets to disconnect a device from the network."""
    logging.info(f"[ACTION] Sending deauthentication packets to disconnect device: {mac}")
    try:
        # Construct deauthentication packet
        packet = RadioTap()/Dot11(addr1=mac, addr2="ff:ff:ff:ff:ff:ff", addr3="ff:ff:ff:ff:ff:ff")/Dot11Deauth(reason=7)
        # Send the packet
        scapy.sendp(packet, iface=interface, count=10, inter=0.1, verbose=False)
        logging.info(f"[SUCCESS] Deauthentication packets sent to {mac}")
    except Exception as e:
        logging.error(f"[ERROR] Failed to send deauthentication packets to {mac}. Error: {e}")

def block_device_with_firewall(mac):
    """Blocks a device at the firewall level using iptables."""
    logging.info(f"[ACTION] Blocking device {mac} at the firewall level.")
    try:
        # Add an iptables rule to drop packets from the MAC address
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"], check=True)
        logging.info(f"[SUCCESS] Device {mac} has been blocked at the firewall level.")
    except subprocess.CalledProcessError as e:
        logging.error(f"[ERROR] Failed to block device {mac} at the firewall level. Error: {e}")

def alert_new_device(mac, ip):
    """Alerts if a device with a new MAC address is detected and disconnects it if blacklisted."""
    if mac in blacklisted_devices:
        logging.info(f"[ALERT] Blacklisted device detected: {mac}. Taking immediate action.")
        send_email_alert("Blacklisted Device Detected", f"Device {mac} was detected and blocked.")
        disconnect_device(mac)
        return

    if mac not in known_devices:
        known_devices.add(mac)
        vendor = "Unknown"
        if mac_lookup:
            try:
                vendor = mac_lookup.lookup(mac.upper())
            except VendorNotFoundError:
                vendor = "Vendor Not Found in Database"
            except Exception as e:
                vendor = f"Error during lookup: {e}"

        logging.info(f"\n[ALERT] New device detected!")
        logging.info(f"  MAC Address: {mac}")
        logging.info(f"  IP Address:  {ip}")
        logging.info(f"  Manufacturer:{vendor}\n")

        # Optionally disconnect the device and add to blacklist
        disconnect_device(mac)
        block_device_with_firewall(mac)
        blacklisted_devices[mac] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logging.info(f"[INFO] Device {mac} has been added to the blacklist.")

def detect_mac_spoofing(mac, ip):
    """Detects MAC address spoofing by checking if the same MAC address is associated with multiple IPs."""
    if mac in known_devices:
        for device_ip in known_devices:
            if device_ip != ip:
                logging.warning(f"[WARNING] Potential MAC spoofing detected for MAC: {mac}. IPs: {device_ip}, {ip}")
                send_email_alert("MAC Spoofing Detected", f"MAC: {mac} is associated with multiple IPs: {device_ip}, {ip}")
                return True
    return False

# Intrusion detection configuration
ARP_REQUEST_THRESHOLD = 10  # Number of ARP requests per minute to trigger an alert
arp_request_count = defaultdict(int)
last_reset_time = time.time()

def detect_intrusion(packet):
    """Detects unusual network activity, such as excessive ARP requests."""
    global last_reset_time
    current_time = time.time()

    # Reset counters every minute
    if current_time - last_reset_time > 60:
        arp_request_count.clear()
        last_reset_time = current_time

    if packet.haslayer(ARP) and packet.op == 1:  # ARP request
        mac = packet.hwsrc
        arp_request_count[mac] += 1

        if arp_request_count[mac] > ARP_REQUEST_THRESHOLD:
            logging.warning(f"[WARNING] Potential intrusion detected: Excessive ARP requests from MAC: {mac}")
            send_email_alert("Intrusion Detected", f"Excessive ARP requests detected from MAC: {mac}")
            return True
    return False

def process_packet(packet):
    """Processes each packet to detect new devices."""
    if packet.haslayer(ARP) and packet.op == 2:  # ARP reply
        mac = packet.hwsrc
        ip = packet.psrc
        if detect_mac_spoofing(mac, ip):
            return
        alert_new_device(mac, ip)
    if detect_intrusion(packet):
        return

def monitor_network(interface="eth0"):
    """Monitors the network for new devices in real-time."""
    logging.info(f"[*] Monitoring network on interface: {interface}")
    try:
        sniff(iface=interface, store=False, prn=process_packet)
    except Exception as e:
        logging.error(f"[ERROR] Failed to monitor network. Error: {e}")

# Add initial blacklist entries to the blacklist.json file
initial_blacklist = {
    "00:0d:3a:02:37:14": "2025-04-13 08:00:00",
    "b4:92:fe:07:87:54": "2025-04-13 08:00:00"
}

# Save the initial blacklist to the file
BLACKLIST_FILE = "blacklist.json"
with open(BLACKLIST_FILE, "w") as f:
    json.dump(initial_blacklist, f)

def load_blacklist():
    global blacklisted_devices
    try:
        with open(BLACKLIST_FILE, "r") as f:
            blacklisted_devices = json.load(f)
        logging.info(f"[INFO] Blacklist loaded from {BLACKLIST_FILE}.")
    except FileNotFoundError:
        logging.warning(f"[WARN] Blacklist file {BLACKLIST_FILE} not found. Starting with an empty blacklist.")
        blacklisted_devices = {}
    except Exception as e:
        logging.error(f"[ERROR] Failed to load blacklist. Error: {e}")
        blacklisted_devices = {}

# Save blacklist to a file
def save_blacklist():
    try:
        with open(BLACKLIST_FILE, "w") as f:
            json.dump(blacklisted_devices, f)
        logging.info(f"[INFO] Blacklist saved to {BLACKLIST_FILE}.")
    except Exception as e:
        logging.error(f"[ERROR] Failed to save blacklist. Error: {e}")

# Enhanced logging for auditing
def log_audit_event(event):
    """Logs detailed audit events to a separate audit log file."""
    with open("audit_log.txt", "a") as audit_log:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        audit_log.write(f"[{timestamp}] {event}\n")

# Periodic blacklist cleanup
def cleanup_blacklist():
    """Removes old entries from the blacklist after a configurable period."""
    CLEANUP_THRESHOLD_DAYS = 30
    current_time = datetime.datetime.now()
    updated_blacklist = {}

    for mac, timestamp in blacklisted_devices.items():
        entry_time = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
        if (current_time - entry_time).days <= CLEANUP_THRESHOLD_DAYS:
            updated_blacklist[mac] = timestamp
        else:
            log_audit_event(f"Removed expired blacklist entry: {mac}")

    blacklisted_devices.clear()
    blacklisted_devices.update(updated_blacklist)

# Call cleanup_blacklist periodically
if __name__ == "__main__":
    load_blacklist()
    cleanup_blacklist()
    try:
        monitor_network()
    finally:
        save_blacklist()
