print("###############basic paquet sniffer#############")
from scapy.all import *
import time

conf.iface = "Wi-Fi"
packet_count = 0  
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
    8080: "HTTP Alternate / Proxy",
    8443: "HTTPS Alternate",
    8888: "Alternate HTTP",
    9000: "Web / Custom",
    9090: "Web / Custom",
    10000: "Webmin",
    27017: "MongoDB",
    50000: "SAP"
}

udp_ports = {
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    123: "NTP",
    135: "RPC / DCE",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    161: "SNMP",
    162: "SNMP Trap",
    500: "IKE / IPsec",
    520: "RIP",
    546: "DHCPv6 Client",
    547: "DHCPv6 Server",
    623: "IPMI",
    1370: "ms-sql-s",
    1389: "LDAP Alternate",
    1900: "SSDP / UPnP",
    3702: "WS-Discovery",
    4500: "IPsec NAT-T",
    4789: "VXLAN",
    5353: "mDNS",
    5355: "LLMNR",
    4444: "Custom / Metasploit",
    5000: "UPnP / Web Service",
    514: "Syslog",
    33434: "Traceroute (UDP)",
    69: "TFTP",
    137: "NetBIOS NS",
    138: "NetBIOS Datagram",
    161: "SNMP",
    162: "SNMP Trap",
    123: "NTP",
    1900: "SSDP",
    5000: "UPnP / Web Service",
    4500: "IPsec NAT-T",
    4789: "VXLAN",
    3702: "WS-Discovery",
    1370: "ms-sql-s",
    1389: "LDAP Alternate",
    4444: "Custom / Metasploit",
    623: "IPMI",
    443: "QUIC / HTTPS",
    5353: "mDNS",
    67: "DHCP Server",
    68: "DHCP Client",
    123: "NTP",
    520: "RIP",
    69: "TFTP",
    1900: "SSDP"
}

icmp_details = {
    0: {   # Echo Reply
        0: "Echo Reply"
    },
    3: {   # Destination Unreachable
        0: "Net Unreachable",
        1: "Host Unreachable",
        2: "Protocol Unreachable",
        3: "Port Unreachable",
        4: "Fragmentation Needed",
        5: "Source Route Failed",
        6: "Destination Network Unknown",
        7: "Destination Host Unknown",
        8: "Source Host Isolated",
        9: "Network Administratively Prohibited",
        10: "Host Administratively Prohibited",
        11: "Network Unreachable for TOS",
        12: "Host Unreachable for TOS",
        13: "Communication Administratively Prohibited",
        14: "Host Precedence Violation",
        15: "Precedence Cutoff in Effect"
    },
    4: {   # Source Quench (Deprecated)
        0: "Source Quench"
    },
    5: {   # Redirect
        0: "Redirect Datagram for Network",
        1: "Redirect Datagram for Host",
        2: "Redirect for TOS and Network",
        3: "Redirect for TOS and Host"
    },
    8: {   # Echo Request
        0: "Echo Request"
    },
    9: {
        0: "Router Advertisement"
    },
    10: {
        0: "Router Solicitation"
    },
    11: {  # Time Exceeded
        0: "TTL Exceeded",
        1: "Fragment Reassembly Time Exceeded"
    },
    12: {  # Parameter Problem
        0: "Pointer Indicates Error",
        1: "Missing Required Option",
        2: "Bad Length"
    },
    13: {
        0: "Timestamp Request"
    },
    14: {
        0: "Timestamp Reply"
    },
    15: {
        0: "Information Request (Deprecated)"
    },
    16: {
        0: "Information Reply (Deprecated)"
    },
    17: {
        0: "Address Mask Request"
    },
    18: {
        0: "Address Mask Reply"
    },
    # Extended ICMP (RFC / Experimental)
    30: {0: "Traceroute (Deprecated)"},
    31: {0: "Datagram Conversion Error"},
    32: {0: "Mobile Host Redirect"},
    33: {0: "IPv6 Where-Are-You"},  
    34: {0: "IPv6 I-Am-Here"},
    35: {0: "Mobile Registration Request"},
    36: {0: "Mobile Registration Reply"},
    37: {0: "Domain Name Request"},
    38: {0: "Domain Name Reply"},
    39: {0: "SKIP"},
    40: {0: "Photuris"},
    41: {0: "Photuris (Security)"},
    42: {0: "Extended Echo Request"},
    43: {0: "Extended Echo Reply"}
}
print("num        time(s)        src:port         dst:port       proto    type    length     service")

def show_packets(pkt):
    global packet_count

    if IP not in pkt:
        return  

    packet_count += 1

    timestamp = round(time.time(), 3)
    length = len(pkt)

    if TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        if sport in tcp_ports:
            service = "from "+tcp_ports[sport]
        elif dport in tcp_ports:
            service = "to "+tcp_ports[dport]
        else:
            service = "Unknown"
        flags = str(pkt[TCP].flags)
        proto = "TCP"
        print(f"{packet_count:<8} {timestamp:<13} {pkt[IP].src}:{sport:<6} → {pkt[IP].dst}:{dport:<6} {proto:<8} {flags:<7} {length:<7} {service}")
        
    elif UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        if sport in udp_ports:
            service = "from "+udp_ports[sport]
        elif dport in udp_ports:
            service = "to "+udp_ports[dport]
        else:
            service = "Unknown"
        proto = "UDP"
        print(f"{packet_count:<8} {timestamp:<13} {pkt[IP].src}:{sport:<6} → {pkt[IP].dst}:{dport:<6} {proto:<8} {'-':<6} {length:<7} {service}")
        
    elif ICMP in pkt:
        icmp_type = pkt[ICMP].type
        icmp_code = pkt[ICMP].code
        service = icmp_details.get(icmp_type , {}).get(icmp_code, "Unknown ICMP")
        proto = "ICMP"
        print(f"{packet_count:<8} {timestamp:<13} {pkt[IP].src:<17}→ {pkt[IP].dst:<17} {proto:<8} {'-':<6} {length:} {service}")
       
    else:
        proto = "OTHER"
    

pfilt=input("enter a filter if not type non: ").lower()
if pfilt == "help":
    print("""\
 Common filters:
tcp, udp, icmp
port 80, src port 443, dst port 53
host 192.168.0.40, src host 8.8.8.8
tcp and port 443, udp and dst port 53
not tcp, not host 10.0.0.5
tcp and (port 80 or port 443)
""")
elif pfilt == "non" :
    sniff(prn=show_packets,count=100, store=0)
else :
    sniff(filter=pfilt,count=100, prn=show_packets, store=0)




