from scapy.all import rdpcap

packets = rdpcap('app-norton-failed.pcapng')
print(packets[0])
print(packets[0].show())