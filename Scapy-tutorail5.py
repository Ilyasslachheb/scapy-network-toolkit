print("###############basic ARP discovery#############")
from scapy.all import *
import datetime
import time

conf.iface = "Wi-Fi"
import requests

def get_vendor(mac):
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            return response.text.strip()
        else:
            return "Unknown Vendor"
    except:
        return "Lookup Failed"

target = input("enter a targeted network: ")

arp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target)

# -------------------- Inisailize scan --------------------
previous_scan = {}

result = srp(arp_pkt, timeout=3, verbose=0)[0]

print("IP Address\t\tMAC Address\t\tVendor\t\tTimestamp")
print("_"*60)

for sent, received in result:
    ip = received.psrc
    mac = received.hwsrc
    timestamp = datetime.datetime.fromtimestamp(received.time).strftime("%Y-%m-%d %H:%M:%S")
    vendor =get_vendor(mac)

    previous_scan[ip] = mac

    print(f"{ip}\t\t{mac}\t\t{vendor}\t\t{timestamp}")

# -------------------- Constant  CHECK-UP --------------------
while True:
    current_scan = {}

    result = srp(arp_pkt, timeout=3, verbose=0)[0]

    for sent, received in result:
        current_scan[received.psrc] = received.hwsrc

    # -------- Detect IN devices --------
    for ip in current_scan:
        if ip not in previous_scan:
            print(f"[+] NEW DEVICE: {ip} → {current_scan[ip]}")

    # -------- Detect OUT devices --------
    for ip in previous_scan:
        if ip not in current_scan:
            print(f"[-] DEVICE LEFT: {ip} → {previous_scan[ip]}")

    # -------- Detect ARP SPOOFING --------
    for ip in current_scan:
        if ip in previous_scan and previous_scan[ip] != current_scan[ip]:
            print(f"[!] WARNING: MAC CHANGE DETECTED for {ip}")
            print(f"    Old MAC: {previous_scan[ip]}")
            print(f"    New MAC: {current_scan[ip]}")

    previous_scan = current_scan.copy()

    time.sleep(60)
    
