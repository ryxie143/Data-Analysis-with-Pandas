import scapy.all as scapy
from visualizer import global_data
from audio_alert import play_alert

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        print(f"[+] Source IP: {src_ip}")
        global_data['packet_count'] += 1
        play_alert()  # 🔊 Play sound on every packet

def start_sniffing():
    print("[+] Starting packet sniffing...")
    scapy.sniff(prn=packet_callback, store=0, iface="Wi-Fi", timeout=15)
    print("[+] Packet sniffing stopped.")
