# Advanced Network Sniffer

## Project Overview

This project, developed as part of my CodeAlpha internship, focuses on building an advanced network sniffer in Python for Linux OS. The sniffer captures and analyzes network traffic using raw sockets, providing detailed insights into various network protocols.

## Features

- **Comprehensive Packet Capture**: Captures and processes Ethernet frames and detailed information about IPv4, TCP, UDP, and ICMP packets.
  
- **Real-Time Traffic Analysis**: Provides real-time insights into network traffic, including source and destination MAC/IP addresses, ports, and various protocol-specific details.
  
- **Protocol Detection**: Accurately identifies and marks packets of different protocols, including HTTP traffic based on port numbers.
  
- **Detailed Header Parsing**:
  - Ethernet Header: Source and destination MAC addresses, protocol type.
  - IPv4 Header: Version, header length, TTL, protocol, source and destination IP addresses.
  - TCP Header: Source and destination ports, sequence number, acknowledgment number, and flags (URG, ACK, PSH, RST, SYN, FIN).
  - UDP Header: Source and destination ports, length, and checksum.
  - ICMP Header: Type, code, and checksum.
  
- **User-Friendly Output**: Presents parsed data in a clear and structured format, making it easy to understand and analyze network activity.
  
- **Error Handling**: Gracefully handles errors and interruptions, ensuring continuous and reliable packet capture.

## Requirements

- Python 3
- `socket` library
- `struct` library
- `sys` library

## Supportive Resources

To help you understand how this network sniffer works and to deepen your knowledge of networking concepts, here are some resources that were instrumental in achieving this project:

- [TCP/IP Model](https://www.geeksforgeeks.org/tcp-ip-model/)
- [Layers of OSI Model](https://www.geeksforgeeks.org/open-systems-interconnection-model-osi/)
- [What is Network Traffic?](https://www.fortinet.com/resources/cyberglossary/network-traffic)
- [Sockets in Operating System](https://youtu.be/uagKTbohimU?si=UxtWhaebrlkvWH__)
- [Packet sniffer in Python](https://www.uv.mx/personal/angelperez/files/2018/10/sniffers_texto.pdf)
- [INTERNET PROTOCOL (RFC 791)](https://tools.ietf.org/html/rfc791)

## Note

Ensure you run the script with root privileges to access the network interface for capturing packets:

```bash
sudo python3 Basic_Network_Sniffer.py
