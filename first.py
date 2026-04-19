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
<<<<<<< HEAD
total_packets = 0
all_ip = set()
total_count = {}

=======
>>>>>>> 6e95a4bcbb6f8d601489e96bf379cf90311092ea
for pkt in packets:
    ts = datetime.fromtimestamp(float(pkt.time))
    proto = pkt.lastlayer().name
    
    print(pkt.keys())
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        print(f"{ts} {proto:8} {src} -> {dst}")
        # adds endpoints to a set (start, end)
        all_ip.add(src)
        all_ip.add(dst)
        endpoints.add((src, dst))
        # count packets sent and received
        total_packets += 1
        if src in total_count:
            total_count[src][0] += 1
        else:
            total_count[src] = [1,0]
        if dst in total_count:
            total_count[dst][1] += 1
        else:
            total_count[dst] = [0,1]

# total number of packets sent
print(f"Total packets sent: {total_packets}")
# number of packets sent and received by each IP
for address in all_ip:
    print(f"IP: {address}; total packets sent is {total_count[address][0]} and total received is {total_count[address][1]}")
print(endpoints)

