import socket
import struct
import base64
import urllib.parse
from colorama import Fore, Style, init
import pyfiglet

# Initialize colorama
init(autoreset=True)

def display_banner():
    banner = pyfiglet.figlet_format("DNS Packet Crafter")
    print(Fore.YELLOW + banner)
    print(Fore.WHITE + "[>] Welcome to the DNS Packet Crafter! [<]")

def obfuscate_payload(payload, method):
    """
    Obfuscates the payload using the specified method.
    Supported methods: Base64, URLEncode, Hexadecimal, None.
    """
    if method == "Base64":
        return base64.b64encode(payload).decode()
    elif method == "URLEncode":
        return urllib.parse.quote(payload)
    elif method == "Hexadecimal":
        return ''.join(f"{byte:02x}" for byte in payload)
    elif method == "None":
        return payload.decode()  # No obfuscation applied
    else:
        raise ValueError("[!] Unsupported obfuscation method!")

def create_dns_query(domain, obfuscation="None"):
    """
    Constructs a DNS query for the given domain with optional obfuscation.
    """
    # DNS Header: ID, Flags, Questions, Answer RRs, Authority RRs, Additional RRs
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)

    # DNS Question Section: QNAME, QTYPE (A), QCLASS (IN)
    qname = b''.join([bytes([len(part)]) + part.encode() for part in domain.split('.')]) + b'\x00'
    qtype_qclass = struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
    query = header + qname + qtype_qclass

    if obfuscation != "None":
        print(f"[+] Applying {obfuscation} obfuscation.")
        return obfuscate_payload(query, obfuscation).encode()

    return query

def send_dns_query(target_ip, domain, obfuscation):
    """
    Sends a DNS query to the specified target IP and displays the response.
    """
    query = create_dns_query(domain, obfuscation)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)  # 3-second timeout

    try:
        print(f"[+] Sending DNS query for '{domain}' to {target_ip} (Obfuscation: {obfuscation})")
        sock.sendto(query, (target_ip, 53))  # Sending the query to port 53 (DNS)
        response, _ = sock.recvfrom(512)  # DNS responses are typically <= 512 bytes
        print(f"[+] Received response:\n{response}")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    display_banner();
    # User inputs
    target_ip = input("Enter the target DNS server IP: ").strip()
    domain = input("Enter the domain to query: ").strip()

    # Obfuscation method selection
    print("\n[+] Select obfuscation method:")
    print("1. Base64\n2. URLEncode\n3. Hexadecimal\n4. None")
    choice = input("Enter your choice: ").strip()

    # Map choice to obfuscation method
    methods = {"1": "Base64", "2": "URLEncode", "3": "Hexadecimal", "4": "None"}
    obfuscation = methods.get(choice, "None")

    # Send the DNS query
    send_dns_query(target_ip, domain, obfuscation)

