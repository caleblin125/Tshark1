import subprocess
import re
import requests
import math
from scapy.all import rdpcap, IP, TCP
from datetime import datetime
from collections import Counter
from vpython import *

# --- 1. CONFIG & PCAP LOADING ---
try:
    with open("capfile.txt", 'r') as file:
        capfile = file.readline().strip() # Removes hidden \n
    print(f"Opening: {capfile}")
    packets = rdpcap(capfile)
except Exception as e:
    print(f"File Error: {e}")
    exit()

# --- 2. PACKET ANALYSIS ---
syns = Counter()
for pkt in packets:
    if IP in pkt and TCP in pkt:
        # Check for SYN (0x02) and NOT ACK (0x10)
        if (pkt[TCP].flags & 0x02) and not (pkt[TCP].flags & 0x10):
            syns[pkt[IP].src] += 1

for src, count in syns.most_common():
    if count >= 20:
        print(f"[SCAN DETECTED] {src} sent {count} SYNs")

# --- 3. TRACEROUTE & GEO ---
def run_traceroute(target):
    # Fixed: subprocess is now imported
    result = subprocess.run(['traceroute', '-n', '-m', '30', target], 
                            capture_output=True, text=True)
    return result.stdout

def parse_hops(output):
    hops = []
    for line in output.splitlines()[1:]:
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
        rtt_match = re.findall(r'(\d+\.\d+)\s+ms', line)
        if ip_match:
            # Fixed: Properly closed dictionary
            hops.append({
                'ip': ip_match.group(1),
                'rtt': float(rtt_match[0]) if rtt_match else None
            })
    return hops

def geolocate(ip):
    try:
        r = requests.get(f'http://ip-api.com/json/{ip}', timeout=3)
        d = r.json()
        if d['status'] == 'success':
            return d['lat'], d['lon'], d.get('city', 'Unknown')
    except: return None
    return None

# --- 4. 3D VISUALIZATION ---
def visualize(hops):
    scene.title = "Network Path 3D"
    scene.background = color.black
    prev_pos = None

    for i, hop in enumerate(hops):
        geo = geolocate(hop['ip'])
        if not geo: continue
        
        lat, lon, city = geo
        # Coordinates: x=lon, y=lat, z=hop distance
        pos = vector(lon/10, lat/10, i * 2)
        
        # Color by RTT
        rtt = hop['rtt']
        c = color.green if (rtt and rtt < 50) else (color.yellow if (rtt and rtt < 150) else color.red)
        
        sphere(pos=pos, radius=0.4, color=c)
        label(pos=pos + vector(0, 0.5, 0), text=f"Hop {i+1}\n{hop['ip']}\n{city}", height=8)

        if prev_pos:
            curve(pos=[prev_pos, pos], color=color.cyan, radius=0.05)
        prev_pos = pos

# --- 5. EXECUTION ---
TARGET = "8.8.8.8"
print(f"Tracing to {TARGET}...")
hops = parse_hops(run_traceroute(TARGET))
visualize(hops)

while True:
    rate(10)