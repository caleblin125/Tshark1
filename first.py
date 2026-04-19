from scapy.all import rdpcap, IP
from datetime import datetime

packets = rdpcap(r'C:\Users\Kay\Desktop\Hackathon CNSA\app-norton-failed.pcapng')
print(packets[0])
print(packets[0].show())

endpoints = set()

for pkt in packets:
    ts = datetime.fromtimestamp(float(pkt.time))
    proto = pkt.lastlayer().name

    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        print(f"{ts} {proto:8} {src} -> {dst}")
        # adds endpoints to a set (stard, end)
        endpoints.add((src, dst))
print(endpoints)