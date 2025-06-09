from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from colorama import Fore, Style, init
from collections import defaultdict
import csv
import datetime

# Initialize colorama
init(autoreset=True)

# File name with timestamp
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
csv_file = f"packet_log_{timestamp}.csv"

# Counter for suspicious IP detection
ip_counter = defaultdict(int)

# Open CSV file and prepare writer
with open(csv_file, mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["Timestamp", "Source IP", "Destination IP", "Protocol", "Length"])

    def process_packet(packet):
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            src = ip_layer.src
            dst = ip_layer.dst
            proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else ip_layer.proto
            pkt_len = len(packet)
            time_str = datetime.datetime.now().strftime("%H:%M:%S")

            # Print details in color
            print(Fore.CYAN + f"[{time_str}] {src} → {dst} | Protocol: {proto} | Size: {pkt_len} bytes")

            # Write to CSV
            writer.writerow([time_str, src, dst, proto, pkt_len])

            # Basic anomaly detection
            ip_counter[src] += 1
            if ip_counter[src] > 15:
                print(Fore.RED + f"[!] Suspicious activity: {src} sent {ip_counter[src]} packets!")

    # Start sniffing with graceful exit
    try:
        print(Fore.GREEN + "🚀 Sniffing started... Press Ctrl+C to stop.\n")
        sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n🛑 Sniffing stopped by user.")
