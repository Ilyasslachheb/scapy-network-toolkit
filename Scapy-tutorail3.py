from scapy.all import *
import time

print("###############basic tracerout#############")
dst_ip = input("Enter destination IP: ")

conf.iface = "Wi-Fi"
lin=""
for ttl in range(1, 30):
    print(f"TTL={ttl} →", end="")

    # Build packet
    pkt = IP(dst=dst_ip, ttl=ttl) / ICMP(type=8, id=0x1234, seq=ttl)

    # Send time calculate rtt
    start = time.time()
    reply = sr1(pkt, timeout=2, verbose=0)
    end = time.time()

    rtt = round((end - start) * 1000, 2)
    # No response
    if reply is None:
        print("* timeout")
        continue

    # Hop router
    if reply.haslayer(ICMP) and reply[ICMP].type == 11:
        print(f"{reply.src}   {rtt} ms")
        continue

    # Destination reached
    if reply.haslayer(ICMP) and reply[ICMP].type == 0:
        print(f"{reply.src}   {rtt} ms  (destination)")
        break
        
    
        