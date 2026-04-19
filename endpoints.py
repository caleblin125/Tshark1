from scapy.all import rdpcap, IP
from datetime import datetime

def get_packet_details(capfile):
    packets = rdpcap(capfile)
    packet_list = []
    seen_connections = set()

    for pkt in packets:
        if IP in pkt:
            # Formatting for the HTML table
            ts = datetime.fromtimestamp(float(pkt.time)).strftime('%H:%M:%S')
            proto = pkt.lastlayer().name
            src = pkt[IP].src
            dst = pkt[IP].dst
            
            conn_key = (src, dst, proto)
            
            if conn_key not in seen_connections:
                # This is what actually goes to the HTML
                packet_list.append({
                    'time': ts,
                    'src': src,
                    'dst': dst,
                    'proto': proto
                })
                seen_connections.add(conn_key)
                
    return packet_list # CRITICAL: This sends the data back to interface.py