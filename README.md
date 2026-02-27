# scapy-network-toolkit
Scapy Network Toolkit 🚀
A progressive, project-based exploration of network protocols and packet manipulation using Scapy. This repository documents my transition from basic packet cloning to building advanced network security tools.

🛠 Project Roadmap
Instead of traditional theory, I learned by building. Each script represents a "level up" in technical complexity:

Scapy-tutorail1.py | The Packet Clone: A foundational exercise in manual packet construction. I captured ICMP traffic in Wireshark and replicated it bit-for-bit to understand packet headers.

Scapy-tutorail2.py | Custom Ping: My first interaction with network communication—sending ICMP echo requests and handling the replies.

Scapy-tutorail3.py | Traceroute Logic: Manipulating the Time-To-Live (TTL) field to map out network hops and understand how packets traverse the internet.

Scapy-tutorail4.py | Mini-Sniffer: A real-time traffic analyzer. This script captures live packets and parses raw data into a human-readable format, similar to a command-line Wireshark.

Scapy-tutorail5.py | ARP Guardian: An advanced network discovery tool that:

Maps all active devices on a network via ARP broadcasts.

Identifies device manufacturers.

Detects ARP Spoofing by monitoring MAC address changes.

Scapy-tutorail6.py | TCP Port Scanner: A robust CLI tool built with argparse. It performs SYN scans to detect open/closed ports and identifies the running services.

🚀 Getting Started
Prerequisites
Python 3.x

Scapy library

Root/Administrative privileges (required for raw packet manipulation)

Installation
Bash
pip install scapy
Usage Example (Level 6 Scanner)
Bash
# Scan a range of ports
sudo python3 Scapy-tutorail6.py 192.168.1.1 -r 20-443

# Scan specific ports
sudo python3 Scapy-tutorail6.py 192.168.1.1 -m 80,443,8080
💡 Lessons Learned
Protocol Anatomy: Deep understanding of Layer 2 (Ethernet), Layer 3 (IP/ICMP), and Layer 4 (TCP/UDP) headers.

Network Security: Practical exposure to how ARP spoofing works and how to defend against it.

Automation: Transitioning from manual packet crafting to building automated, user-friendly CLI tools.
