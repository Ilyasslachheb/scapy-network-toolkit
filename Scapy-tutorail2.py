print("###############basic ping#############")
from scapy.all import *

conf.iface = "Wi-Fi

dst_ip = input("Enter destination IP: ")

for i in range(1, 5):
    print(f"\nSending ICMP Echo Request #{i}...")

    pkt = IP(dst=dst_ip, ttl=64)/ICMP(type=8, id=0x1234, seq=i)/Raw(load="abcdefghijklmnopqrstuvwabcdefghi")

    ans = sr1(pkt, timeout=2, verbose=False)

    if ans:
        print("✔ Reply received from", ans.src)
    else:
        print("✘ No reply")


