import base64
import urllib.parse
import codecs
from scapy.all import IP, TCP, send
import socket
import subprocess
from colorama import Fore, Style, init
import pyfiglet

# Initialize colorama
init(autoreset=True)

def display_banner():
    banner = pyfiglet.figlet_format("FTP Packet Crafter")
    print(Fore.YELLOW + banner)
    print(Fore.WHITE + "[>] Welcome to the FTP Packet Crafter! [<]")

# Obfuscation functions
def base64_encode(payload):
    encoded_payload = base64.b64encode(payload.encode('utf-8')).decode('utf-8')
    return encoded_payload

def url_encode(payload):
    encoded_payload = urllib.parse.quote(payload, safe='')
    return encoded_payload

def hex_encode(payload):
    encoded_payload = payload.encode('utf-8').hex()
    return encoded_payload

def xor_encrypt(payload, key=0xAA):
    encrypted_payload = ''.join(chr(ord(c) ^ key) for c in payload)
    return encrypted_payload

def rot13_encrypt(payload):
    encrypted_payload = codecs.encode(payload, 'rot_13')
    return encrypted_payload

def case_swap(payload):
    return payload.swapcase()

def bashfuscator_obfuscate(payload):
    command = ["bashfuscator", "-c", payload, "--choose-mutators", "command/case_swapper", "-s", "1"]
    result = subprocess.run(command, text=True, capture_output=True, check=True)
    return result.stdout.strip()

# Function to display obfuscation options and apply user's choice
def obfuscate_payload(payload):
    print(Fore.CYAN + "\nChoose an obfuscation method:")
    print(Fore.YELLOW + "1. Base64 Encode")
    print(Fore.YELLOW + "2. URL Encode")
    print(Fore.YELLOW + "3. Hex Encode")
    print(Fore.YELLOW + "4. XOR Encrypt")
    print(Fore.YELLOW + "5. ROT-13 Encrypt")
    print(Fore.YELLOW + "6. Case Swap")
    print(Fore.YELLOW + "7. Bashfuscator")
    print(Fore.YELLOW + "8. No Obfuscation")
    
    choice = int(input(Fore.GREEN + "Enter your choice (1-8): "))

    if choice == 1:
        return base64_encode(payload)
    elif choice == 2:
        return url_encode(payload)
    elif choice == 3:
        return hex_encode(payload)
    elif choice == 4:
        key = int(input(Fore.GREEN + "Enter XOR key (default is 170): ") or "170")
        return xor_encrypt(payload, key)
    elif choice == 5:
        return rot13_encrypt(payload)
    elif choice == 6:
        return case_swap(payload)
    elif choice == 7:
        return bashfuscator_obfuscate(payload)
    elif choice == 8:
        return payload
    else:
        print(Fore.RED + "Invalid choice. Sending original payload.")
        return payload

# Proxy function to send traffic through the local proxy
def send_through_proxy(proxy_ip, proxy_port, target_ip, target_port, payload):
    # Create socket to communicate through the proxy
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((proxy_ip, proxy_port))  # Connect to the proxy
        # Sending the FTP packet through the proxy
        s.sendall(payload.encode() + b"\r\n")
        response = s.recv(1024)
        print(Fore.GREEN + f"Proxy Response: {response.decode()}")

# Main script
display_banner()

source_ip = input(Fore.CYAN + "Enter the source IP: ")
source_port = int(input(Fore.CYAN + "Enter the source port: "))
destination_ip = input(Fore.CYAN + "Enter the destination IP: ")
destination_port = int(input(Fore.CYAN + "Enter the destination port: "))
payload = input(Fore.CYAN + "Enter the payload to send: ")

# Apply obfuscation
obfuscated_payload = obfuscate_payload(payload)

# Display the payload summary using pyfiglet
ascii_banner = pyfiglet.figlet_format("Payload Summary", font="slant")
print(Fore.MAGENTA + ascii_banner)

# Display the obfuscated payload
print(Fore.GREEN + "Crafted Payload:")
print(Fore.YELLOW + obfuscated_payload)

# Prompt for proxy configuration
proxy_ip = "127.0.0.1"
proxy_port = 21

# Send the FTP packet through the proxy
send_through_proxy(proxy_ip, proxy_port, destination_ip, destination_port, obfuscated_payload)

