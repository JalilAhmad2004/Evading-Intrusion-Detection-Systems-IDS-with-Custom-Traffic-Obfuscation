# Evading-Intrusion-Detection-Systems-IDS-with-Custom-Traffic-Obfuscation

## Project Overview
This project explores techniques for evading Intrusion Detection Systems (IDS), specifically focusing on Snort, through custom traffic obfuscation. By implementing various obfuscation techniques, we analyze how IDS can be bypassed using specially crafted network packets.

## Team Members
- **Muhammad Umer Farooq**
- **Jalil Ahmad**
- **Talha Asghar**

## Project Scope
- Creation of a lab environment with Kali Linux (attacker) and a victim Linux machine running Snort IDS.
- Development of a Python-based tool capable of generating obfuscated network traffic.
- Implementation of an intermediary proxy to monitor and analyze traffic flow.
- Evaluation of IDS evasion techniques against Snort community and subscriber rules.
- Documentation of findings and obfuscation techniques.

## Dependencies
This project uses various tools and libraries to achieve traffic obfuscation:
- **Python (Scapy Library)**: Used to craft and manipulate network packets.
- **Nmap**: For executing network scans with evasion techniques.
- **Bashfuscator**: To obfuscate bash commands in various payloads.

## Implementation
The project includes several Python scripts implementing different traffic obfuscation methods. Below are the key components:

### Evil Payload Crafter Tool
A custom Python-based tool using Scapy that allows us to craft and manipulate TCP and UDP packets. Supported functionalities:
- SQL Packet Crafter
- SMTP Payload Crafter
- DNS Query Obfuscation
- FTP Payload Crafter
- HTTP Payload Crafter
- Backdoor and DDoS Crafting
- Telnet Packet Crafter

### Nmapping Tools
A collection of scripts leveraging Nmap to perform advanced network scanning while evading IDS detection. Techniques include:
- Decoy Scan
- Fragment Packets
- MAC Address Spoofing
- Source Port Manipulation
- IP Spoofing
- Firewalk
- Zombie Scan
- Bad Checksum
- Obfuscation
- Protocol Violations
- TTL Manipulation

### Evil Proxy
A custom proxy designed to sit between the attacker and the destination machine, allowing real-time monitoring and modification of network traffic.

### Traffic Obfuscation Techniques
The scripts implement multiple obfuscation strategies, including:
- **Base64 Encoding**
- **Hex Encoding**
- **ROT-13 Obfuscation**
- **URL Encoding**
- **Protocol Switching (TCP ↔ UDP)**

## Snort Rules and Testing
We have tested these obfuscation techniques against various Snort IDS rules, analyzing how effectively different methods can bypass detection.

## Limitations
- A real-time traffic modification proxy was not implemented due to complexity, so Scapy is used instead for direct packet manipulation.

## Installation & Usage
### Prerequisites
Ensure the following dependencies are installed on your system:
- Python 3.x
- Scapy (`pip install scapy`)
- Nmap (`sudo apt install nmap`)
- Bashfuscator (for bash obfuscation techniques)

### Running the Scripts
Clone the repository and navigate to the project directory:
```sh
git clone https://github.com/your-repo-link
cd your-repo-link
```
Run the payload crafter:
```sh
python evil_payload_crafter.py
```
Run the network mapping tools:
```sh
python nmapping_tools.py
```

## Conclusion
This project provides valuable insights into IDS evasion techniques using traffic obfuscation. By analyzing Snort’s detection capabilities, we aim to highlight potential vulnerabilities in signature-based IDS solutions and contribute to the field of penetration testing and cybersecurity research.

## Authors & License
This project was developed as part of the CY3001 Networks & Cyber Security-II course. Licensed under [MIT License](LICENSE).

---
*For research and educational purposes only. Unauthorized use of these techniques in real-world environments is strictly prohibited.*


