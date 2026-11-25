# CodeAlpha_BasicNetworkSniffer

A Python-based real-time network packet sniffer built using **Scapy** as part of the **CodeAlpha Cyber Security Internship**.

## Features
- Captures live IPv4 network packets in real time.
- Identifies protocols (**TCP**, **UDP**, **ICMP**) with color-coded terminal output.
- Extracts **Source IP**, **Destination IP**, **Source/Destination Ports**, and readable **Payload** previews.
- Supports Berkeley Packet Filters (BPF) such as `tcp`, `udp`, `icmp`, or `port 443`.
- Automatically exports captured packets to a `.pcap` file (can be opened in Wireshark).

## Prerequisites (Windows)
1. Install **Python 3.8+**.
2. Install **Npcap** (required by Scapy on Windows to capture live packets):
   - Download from [npcap.com](https://npcap.com/#download) and check *"Install Npcap in WinPcap API-compatible Mode"* during installation.

## Installation & Usage

```bash
# Clone the repository
git clone [https://github.com/rauta8522-lang/CodeAlpha_BasicNetworkSniffer.git](https://github.com/rauta8522-lang/CodeAlpha_BasicNetworkSniffer.git)
cd CodeAlpha_BasicNetworkSniffer

# Install dependencies
pip install -r requirements.txt

# Run as Administrator (Capture 25 packets)
python sniffer.py -c 25

# Filter only TCP traffic
python sniffer.py -f "tcp" -c 30