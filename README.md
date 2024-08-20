# Power-Deauther
Usage: deauth.py options

Deauth unwanted users from a Wi-Fi network.

### Options:
- -h, --help  
  Show this help message and exit.

- --deauth_reasons DEAUTH_REASONS [DEAUTH_REASONS ...]  
  List of deauth codes to be sent sequentially to the target. Default is all: [1, 2, 3, 4, 6, 7, 8, 10].

- --deauth_seq DEAUTH_SEQ  
  Number of packets for each reason to be sent at once. Default is 50.

- --whitelist_ap WHITELIST_AP [WHITELIST_AP ...]  
  Ignore these ESSID or BSSID APs from attacking.

- --whitelist_client WHITELIST_CLIENT [WHITELIST_CLIENT ...]  
  Ignore these clients from attacking.

- --blacklist_ap BLACKLIST_AP [BLACKLIST_AP ...]  
  List of ESSID or BSSID AP targets.

- --blacklist_client BLACKLIST_CLIENT [BLACKLIST_CLIENT ...]  
  List of client targets.

- --attack_all_ap  
  Allows using empty blacklist lists and attacks all found APs, except for whitelist.

- --attack_all_client  
  Allows using empty blacklist lists and attacks all found clients, except for whitelist.

- --channel_list CHANNEL_LIST [CHANNEL_LIST ...]  
  Channels to hop. Default includes all 2.4GHz and 5GHz channels.

- --scan_wait SCAN_WAIT  
  Duration (in seconds) to scan. Default is 30.