import socket
import pandas as pd
import json
import time

# ---- IP ADDRESS AUR PORT ----
HOST = '10.24.135.178' 
PORT = 9090
FILE_PATH = 'data.xlsx'

# ---- FILTERING PARAMETERS ----
ROW_COUNT = 5     # Shuru ki kitni rows bhejni hain
COLUMN_COUNT = 6  # Shuru ke kitne columns bhejne hain

try:
    df = pd.read_excel(FILE_PATH)
    
    # 1. CORE FILTER: Rows aur Columns ko ek sath slice karo
    df = df.iloc[0:ROW_COUNT, 1:COLUMN_COUNT] 
    
    # 2. METADATA: Filter hone ke baad jo columns bache, unke headers nikal lo
    headers_list = df.columns.tolist()
    
except FileNotFoundError:
    print(f"[!] Error: '{FILE_PATH}' not found in the directory.")
    exit()

def start_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT))
            print(f"[+] Connected to Control Center.")
            
            # Terminal par explicitly headers print kar rahe hain
            print(f"[*] Active Column Headers: {headers_list}")
            print(f"[*] Streaming {len(df)} rows...\n")
            
            for index, row in df.iterrows():
                payload = {
                    "sensor_id": "Grid_Node_01",
                    "data": row.to_dict() # .to_dict() automatically headers ko JSON keys me map kar deta hai
                }
                
                json_payload = json.dumps(payload) + '\n' 
                s.sendall(json_payload.encode('utf-8'))
                
                print(f"> Transmitted [Row {index}]: {json_payload.strip()}")
                time.sleep(2) 
            
            print("\n[+] Transmission strictly complete. Shutting down client.")
            
        except ConnectionRefusedError:
            print("[!] Connection Refused: Is the server running and firewall off?")
        except KeyboardInterrupt:
            print("\n[-] Data stream manually terminated.")

if __name__ == "__main__":
    start_client()