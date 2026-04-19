from scapy.all import *
import re

with open("capfile.txt", 'r') as file:
    capfile = file.readline().strip()

streams = {}
filenames = {}

def process(pkt):
    if not (pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP)):
        return

    key = tuple(sorted([
        (pkt[IP].src, pkt[TCP].sport),
        (pkt[IP].dst, pkt[TCP].dport)
    ]))
    
    payload_bytes = pkt[Raw].load
    payload = payload_bytes.decode(errors='ignore')

    # --- 1. Collect stream ---
    streams.setdefault(key, b"")
    streams[key] += payload_bytes

    # --- 2. Extract filename from GET ---
    if payload.startswith("GET "):
        try:
            path = payload.splitlines()[0].split(" ")[1]
            name = path.split("/")[-1]
            if "." in name:
                filenames[key] = name
                print(f"[GET] {name} from {key}")
        except:
            pass

    # --- 3. Extract filename from headers ---
    match = re.search(r'filename="?([^"]+)"?', payload)
    if match:
        filenames[key] = match.group(1)
        print(f"[HDR] {filenames[key]} from {key}")

# --- Run once ---
sniff(offline=capfile, prn=process, store=0)

# --- Analyze streams ---
for key, data in streams.items():
    if b'MZ' in data:
        name = filenames.get(key, "unknown.exe")
        print(f"[!] EXE found in stream {key} → {name}")

        # optional save
        # with open(name, "wb") as f:
        #     f.write(data)