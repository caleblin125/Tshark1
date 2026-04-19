from scapy.all import rdpcap, IP, TCP
from datetime import datetime
from collections import Counter

packets = rdpcap('app-norton-failed.pcapng')
print(packets[0])
packets[0].show()

for pkt in packets:
    ts = datetime.fromtimestamp(float(pkt.time))
    proto = pkt.lastlayer().name

    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        print(f"{ts} {proto:8} {src} -> {dst}")

PCAP = "app-norton-failed.pcapng"
THRESHOLD = 20 # SYNs in the capture to flag a source
# Filter = only TCP packets with SYN set, ACK not set
packets = rdpcap(PCAP)
syns = Counter()
for pkt in packets:
    if IP in pkt and TCP in pkt:
        tcp = pkt[TCP]
        if (tcp.flags & 0x02) and not (tcp.flags & 0x10):
            syns[pkt[IP].src] += 1
# Anyone over the threshold gets a finding
for src, count in syns.most_common():
    if count >= THRESHOLD:
        print(f"[SCAN] {src} sent {count} SYNs" )