# Tshark1 — PCAP Threat Explorer

A small web app for triaging network captures. Upload a `.pcap` / `.pcapng`
file and it lists the endpoints and protocols in the capture and flags
suspicious activity such as **executables transferred over the network**.
Built in one day (April 2026) by a team of four, using Python,
[Scapy](https://scapy.net/), and Flask.

## Features

* **Endpoint table** ([`endpoints.py`](endpoints.py)): unique
  source → destination connections with timestamp and top-layer protocol.
* **Executable detection** ([`detect_exe.py`](detect_exe.py)): reassembles TCP
  streams, recovers file names from HTTP `GET` paths and `Content-Disposition`
  headers, and flags streams containing a Windows PE header (`MZ` … `PE`).
* **Plaintext credential scan** ([`plaintxt_creds.py`](plaintxt_creds.py)):
  looks for credentials sent in the clear over HTTP, FTP, and Telnet.
* **Exploration scripts** ([`first.py`](first.py), [`first2.py`](first2.py)):
  SYN counts per source (a simple port-scan signal), packet counts, and a
  traceroute-based 3D view of hops.

## Run

```bash
pip install flask scapy werkzeug
python interface.py          # http://127.0.0.1:5000
```

Upload a capture on the home page; results appear in the endpoints and alerts
tabs. Uploaded files are saved to `uploads/`.

> Only analyze captures you are authorized to inspect.

## Team

[Caleb Lin](https://github.com/caleblin125), Kaylee, Anthony Thomas La, and Nathan.
