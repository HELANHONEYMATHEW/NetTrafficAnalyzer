import threading
import datetime
import csv
from collections import defaultdict
from tkinter import *
from tkinter.scrolledtext import ScrolledText
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

# Initialize packet log file
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
csv_file = f"packet_log_{timestamp}.csv"
writer = open(csv_file, "w", newline='')
csv_writer = csv.writer(writer)
csv_writer.writerow(["Time", "Source IP", "Destination IP", "Protocol", "Length"])

# Global flag to control sniffing
sniffing = False
ip_counter = defaultdict(int)

# GUI Setup
root = Tk()
root.title("CyberSniffer - Network Packet Sniffer")
root.geometry("800x500")

text_area = ScrolledText(root, font=("Courier", 10))
text_area.pack(fill=BOTH, expand=True)

status_label = Label(root, text="Status: Idle", fg="blue")
status_label.pack(pady=5)

# Packet processing function
def process_packet(packet):
    if not sniffing:
        return
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else ip_layer.proto
        pkt_len = len(packet)
        time_str = datetime.datetime.now().strftime("%H:%M:%S")

        # Log to GUI
        log = f"[{time_str}] {src} → {dst} | Protocol: {proto} | Size: {pkt_len} bytes\n"
        text_area.insert(END, log)
        text_area.see(END)

        # Write to CSV
        csv_writer.writerow([time_str, src, dst, proto, pkt_len])

        # Detect suspicious IP
        ip_counter[src] += 1
        if ip_counter[src] > 15:
            alert = f"[!] Suspicious activity: {src} sent {ip_counter[src]} packets!\n"
            text_area.insert(END, alert)
            text_area.see(END)

# Threaded sniffing function
def start_sniff():
    global sniffing
    sniffing = True
    status_label.config(text="Status: Sniffing...", fg="green")
    threading.Thread(target=lambda: sniff(prn=process_packet, store=False)).start()

def stop_sniff():
    global sniffing
    sniffing = False
    status_label.config(text="Status: Stopped", fg="red")
    writer.close()

# Buttons
button_frame = Frame(root)
button_frame.pack(pady=10)

start_btn = Button(button_frame, text="Start Sniffing", bg="green", fg="white", command=start_sniff, width=20)
start_btn.pack(side=LEFT, padx=10)

stop_btn = Button(button_frame, text="Stop Sniffing", bg="red", fg="white", command=stop_sniff, width=20)
stop_btn.pack(side=LEFT, padx=10)

# Launch GUI
root.mainloop()
