from scapy.all import rdpcap, IP, TCP
from datetime import datetime
from collections import Counter
import subprocess
import re
import requests

with open("capfile.txt", 'r') as file:
    capfile = file.readline().strip()

packets = rdpcap(capfile)
print(packets[0])
packets[0].show()

endpoints = set()
for pkt in packets:
    ts = datetime.fromtimestamp(float(pkt.time))
    proto = pkt.lastlayer().name
    
    print(pkt.keys())
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        print(f"{ts} {proto:8} {src} -> {dst}")
        endpoints.add((src, dst))
print(endpoints)

THRESHOLD = 20
syns = Counter()
for pkt in packets:
    if IP in pkt and TCP in pkt:
        tcp = pkt[TCP]
        if (tcp.flags & 0x02) and not (tcp.flags & 0x10):
            syns[pkt[IP].src] += 1

for src, count in syns.most_common():
    if count >= THRESHOLD:
        print(f"[SCAN] {src} sent {count} SYNs")

def run_traceroute(target):
    result = subprocess.run(
        ['traceroute', '-n', '-m', '30', target],
        capture_output=True, text=True
    )
    return result.stdout

def parse_hops(traceroute_output):
    hops = []
    for line in traceroute_output.splitlines()[1:]:
        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
        rtt_match = re.findall(r'(\d+\.\d+)\s+ms', line)
        if match:
            hops.append({
                'ip': match.group(1),
cat > /Users/anthony/Tshark1/first.py << 'EOF'
from scapy.all import rdpcap, IP, TCP
from datetime import datetime
from collections import Counter
import subprocess
import re
import requests

with open("capfile.txt", 'r') as file:
    capfile = file.readline().strip()

packets = rdpcap(capfile)
print(packets[0])
packets[0].show()

endpoints = set()
for pkt in packets:
    ts = datetime.fromtimestamp(float(pkt.time))
    proto = pkt.lastlayer().name
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        print(f"{ts} {proto:8} {src} -> {dst}")
        endpoints.add((src, dst))
print(endpoints)

THRESHOLD = 20
syns = Counter()
for pkt in packets:
    if IP in pkt and TCP in pkt:
        tcp = pkt[TCP]
        if (tcp.flags & 0x02) and not (tcp.flags & 0x10):
            syns[pkt[IP].src] += 1

for src, count in syns.most_common():
    if count >= THRESHOLD:
        print(f"[SCAN] {src} sent {count} SYNs")