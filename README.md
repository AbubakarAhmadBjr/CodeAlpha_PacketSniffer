# Network Traffic Packet Analyzer

A Python‑based network packet sniffer built with Scapy. Captures live traffic and provides detailed analysis including protocol detection, statistics, and logging.

## Features

- Real‑time packet capture (requires Npcap on Windows)
- Protocol detection: TCP, UDP, ICMP, DNS, HTTP, ARP, IPv4/IPv6
- Payload extraction and hex dumps
- Statistics: packet rate, protocol breakdown, top IPs/ports
- Preset capture modes: `http`, `dns`, `icmp`, `arp`, `ssh`, `tcp`, `udp`, `web`
- Logging to JSON, CSV, and plain text
- TCP connection tracking and DNS resolution summary
- Rich terminal output (compact & verbose modes)

## Requirements

- Python 3.8+
- [Npcap](https://npcap.com) (Windows) or libpcap (Linux/macOS)
- Install dependencies: `pip install -r requirements.txt`

## Installation

```bash
git clone https://github.com/AbubakarAhmadBjr/CodeAlpha_PacketSniffer.git
cd CodeAlpha_PacketSniffer
pip install -r requirements.txt
Usage
Note: You must run the script with administrator/root privileges to capture packets.

bash
# List available network interfaces
sudo python main.py --list-interfaces

# Capture all traffic for 10 seconds
sudo python main.py --timeout 10

# Capture DNS traffic only
sudo python main.py --mode dns --timeout 10

# Capture HTTP traffic with verbose output
sudo python main.py --mode http --verbose --count 20

# Use a custom BPF filter
sudo python main.py --filter "host 8.8.8.8 and tcp" --count 50

# Enable logging to files
sudo python main.py --mode dns --log --log-dir my_captures
Output Examples
Compact mode
text
#0012 14:32:01.234 [TCP] 192.168.1.10:54321 → 93.184.216.34:80 150B [SYN,ACK]
Statistics
text
Protocol Breakdown:
Protocol      Count  Percent    Distribution
----------  -------  ---------  ------------------------------
UDP              93  29.5%      ████████░░░░░░░░░░░░░░░░░░░░░░
DNS              88  27.9%      ████████░░░░░░░░░░░░░░░░░░░░░░
TCP              74  23.5%      ███████░░░░░░░░░░░░░░░░░░░░░░░
ARP              58  18.4%      █████░░░░░░░░░░░░░░░░░░░░░░░░░