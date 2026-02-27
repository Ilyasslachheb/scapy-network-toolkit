print("###############basic PORT SCANNER#############")
from scapy.all import *
import time
import argparse

conf.iface = "Wi-Fi"

tcp_ports = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS (TCP)",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    119: "NNTP",
    123: "NTP (TCP)",
    143: "IMAP",
    161: "SNMP (TCP)",
    194: "IRC",
    443: "HTTPS",
    445: "SMB / Microsoft-DS",
    465: "SMTPS",
    514: "Syslog (TCP)",
    515: "LPD",
    587: "SMTP (Submission)",
    631: "IPP Printing",
    636: "LDAPS",
    989: "FTPS Data",
    990: "FTPS Control",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS Proxy",
    1433: "MS SQL Server",
    1521: "Oracle DB",
    1723: "PPTP VPN",
    1883: "MQTT",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel SSL",
    3306: "MySQL",
    3389: "RDP",
    5060: "SIP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Alt / Proxy",
    8443: "HTTPS Alt",
    9000: "Web / Custom",
    9200: "ElasticSearch",
    9300: "ElasticSearch Cluster"
}

COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123,
    137, 138, 139, 143, 161, 389, 443, 445, 514, 587,
    631, 636, 993, 995, 1433, 1521, 1723, 1883,
    2049, 2083, 2087, 2089, 2375, 3306, 3389,
    4443, 5060, 5432, 5672, 5900, 6379, 8080,
    8443, 9000, 9200, 9300
]

#_______________Stores the input from command_______________________

parser = argparse.ArgumentParser()
parser.add_argument("ip_addr", type=str, help="target IP")
parser.add_argument("-p", "--port", type=int, help="scan single port")
parser.add_argument("-m", "--multiple", nargs="+", type=int, help="scan several ports")
parser.add_argument("-r", "--range", nargs=2, type=int, help="scan port range (start end)")

args = parser.parse_args()
dst_ip = args.ip_addr
user_port = args.port
multi_ports = args.multiple
range_ports = args.range

#_______________Scan function___________________________

def scan_port(port):
    pkt = IP(dst=dst_ip) / TCP(dport=port, flags="S")
    reply = sr1(pkt, timeout=1, verbose=0)

    service = tcp_ports.get(port, "Unknown")
    if reply is None:
        print(f"{port}: TIMEOUT ({service})")
        return

    if reply.haslayer(TCP) and reply[TCP].flags == 0x12:
        print(f"{port}: OPEN ---> {service}")
    elif reply.haslayer(TCP) and reply[TCP].flags == 0x14:
        print(f"{port}: BLOCKED ({service})")
    else:
        print(f"{port}: FILTERED ({service})")


#_______________Scan types___________________________

# Default scan
if not user_port and not multi_ports and not range_ports:
    for p in COMMON_PORTS:
        scan_port(p)

# Single port
if user_port:
    scan_port(user_port)

# Multi-port
if multi_ports:
    for p in multi_ports:
        scan_port(p)

# Range scan
if range_ports:
    start, end = range_ports
    for p in range(start, end + 1):
        scan_port(p)