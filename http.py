from scapy.all import IP, TCP, send
import base64
import urllib.parse
import codecs
import socket
from colorama import Fore, Style, init
import pyfiglet

# Initialize colorama
init(autoreset=True)

def display_banner():
    banner = pyfiglet.figlet_format("HTTP Packet Crafter")
    print(Fore.BLUE + banner)

def base64_encode(payload):
    # Encode the payload using base64
    encoded_payload = base64.b64encode(payload.encode('utf-8')).decode('utf-8')
    return encoded_payload

def url_encode(payload):
    # URL encode the payload
    encoded_payload = urllib.parse.quote(payload, safe='')
    return encoded_payload

def hex_encode(payload):
    # Encode the payload to hexadecimal
    encoded_payload = payload.encode('utf-8').hex()
    return encoded_payload

def xor_encrypt(payload, key=0xAA):
    # XOR the payload with a given key (default 0xAA)
    encrypted_payload = ''.join(chr(ord(c) ^ key) for c in payload)
    return encrypted_payload

def rot13_encrypt(payload):
    # Encrypt the payload using ROT-13
    encrypted_payload = codecs.encode(payload, 'rot_13')
    return encrypted_payload

def send_via_proxy(packet, proxy_ip, proxy_port):
    """Send the crafted packet via the proxy server"""
    try:
        # Establish a connection to the proxy
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy_socket:
            proxy_socket.connect((proxy_ip, proxy_port))
            # Send the packet data to the proxy
            proxy_socket.sendall(bytes(packet))
    except Exception as e:
        print(Fore.RED + f"An error occurred while sending the packet via proxy: {e}")

def main():
    # Banner for the script
    display_banner()

    # Get input from the user for source and target details
    print(Fore.CYAN + "[>] Welcome to the HTTP Packet Crafter! [<]")
    source_ip = input("Enter the source IP address: ")
    source_port = int(input("Enter the source port: "))
    target_ip = input("Enter the target IP address: ")
    target_port = int(input("Enter the target port: "))
    
    # Enter proxy server details
    proxy_ip = "127.0.0.1"
    proxy_port = 80
    
    # Allow user to set HTTP payload
    print(Fore.YELLOW + "Enter your payload (type 'EOF' on a new line to finish):")
    lines = []
    
    while True:
        line = input(Fore.WHITE)
        if line.strip().upper() == "EOF":
            break
        lines.append(line)
    
    payload = "\r\n".join(lines) + "\r\n\r\n"
    
    # Asking for appropriate obfuscation techniques
    print(Fore.YELLOW + "[>] What Obfuscation would you want? [<]")
    print(Fore.MAGENTA + "1. Base64")
    print(Fore.MAGENTA + "2. URLEncode")
    print(Fore.MAGENTA + "3. Hexadecimal")
    print(Fore.MAGENTA + "4. XOR Encryption")
    print(Fore.MAGENTA + "5. ROT-13 Encryption")
    print(Fore.MAGENTA + "6. None")
    
    obfuscation_choice = input(Fore.WHITE + "Enter the number corresponding to your choice: ").strip()
    
    if obfuscation_choice == "1":
        payload = base64_encode(payload)
        print(Fore.GREEN + "Encoding Payload in Base64!")
    elif obfuscation_choice == "2":
        payload = url_encode(payload)
        print(Fore.GREEN + "Encoding Payload in URLEncode!")
    elif obfuscation_choice == "3":
        payload = hex_encode(payload)
        print(Fore.GREEN + "Encoding Payload in Hexadecimal!")
    elif obfuscation_choice == "4":
        payload = xor_encrypt(payload)
        print(Fore.GREEN + "Encrypting Payload with XOR!")
    elif obfuscation_choice == "5":
        payload = rot13_encrypt(payload)
        print(Fore.GREEN + "Encrypting Payload with ROT-13!")
    elif obfuscation_choice == "6":
        print(Fore.GREEN + "Not Touching the Payload")
    else:
        print(Fore.RED + "Invalid choice. No obfuscation applied.")
    
    # Displaying the crafted payload
    print(Fore.CYAN + "Your crafted payload:")
    print(Fore.WHITE + payload)
    
    # Construct the packet
    ip_layer = IP(src=source_ip, dst=target_ip)
    tcp_layer = TCP(sport=source_port, dport=target_port, flags="S")
    packet = ip_layer / tcp_layer / payload
    
    try:
        # Send the packet via the proxy
        send_via_proxy(packet, proxy_ip, proxy_port)
        print(Fore.GREEN + "Packet sent via proxy!")
    except Exception as e:
        print(Fore.RED + f"An error occurred: {e}")

if __name__ == "__main__":
    main()

