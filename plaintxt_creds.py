"""
This script is to show the protocol and the source as well as an evidence section 
showing the captured error of the plaintext credentials (HTTP/FTP/Telnet)
"""

from scapy.all import rdpcap, IP, TCP, Raw

# 1. Load your file
filename = "capfile.pcapng" # Change this to your file path
if not os.path.exists(filename):
    print(f"File {filename} not found!")
    exit()

packets = rdpcap(filename)
print(f"--- Scanning {filename} for Security Threats ---\n")

for i, pkt in enumerate(packets):
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst

        # --- RULE R-001: Plaintext Credentials ---
        # We check if there is a Raw layer (the actual data being sent)
        if pkt.haslayer(Raw):
            try:
                # Decode the bytes into text so we can read it
                payload = pkt[Raw].load.decode('utf-8', errors='ignore').lower()
                
                # Check for "USER" or "PASS" (common in FTP/Telnet/HTTP)
                if "user" in payload or "pass" in payload:
                    print(f"[!] ALERT R-001: Plaintext Credentials")
                    print(f"    Source: {src} -> Destination: {dst}")
                    print(f"    Evidence: {payload.strip()}\n")
            except:
                pass

print("--- Scan Complete ---")