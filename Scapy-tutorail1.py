print("###############build paquet#############")
from scapy.all import *
paquets = rdpcap("ICMP-PAQUET.pcap")
pkt=Ether(src="D0:BB:61:AE:58:87", dst="04:ED:33:9C:F3:5B")/IP(src="8.8.8.8", dst="192.168.0.40", ttl=111)/ICMP(id=1, seq=0x14, chksum=0x5547, type="echo-reply")/Raw(load="abcdefghijklmnopqrstuvwabcdefghi")
first_packet = paquets[0]
second_packet = pkt[0]
hexdump(second_packet)
hexdump(first_packet)


wrpcap("capture.pcap", second_packet)



