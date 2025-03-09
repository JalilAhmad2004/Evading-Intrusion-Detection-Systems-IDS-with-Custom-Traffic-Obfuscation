from scapy.all import IP, TCP, UDP, send
import base64
import urllib.parse
import codecs
import pyfiglet
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Display banner using pyfiglet
def print_banner():
    banner = pyfiglet.figlet_format("Packet Sender")
    print(Fore.CYAN + banner)

def send_tcp_packet(src_ip, src_port, dst_ip, dst_port, payload):
    """
    Send a TCP packet using Scapy.
    """
    try:
        # Create the IP and TCP layers with source IP and port
        ip_layer = IP(src=src_ip, dst=dst_ip)
        tcp_layer = TCP(sport=src_port, dport=dst_port)
        
        # Combine layers and the payload
        packet = ip_layer / tcp_layer / payload
        
        print(Fore.GREEN + f"[*] Sending TCP packet from {src_ip}:{src_port} to {dst_ip}:{dst_port}")
        send(packet, verbose=False)
        print(Fore.GREEN + "[*] TCP packet sent successfully!")
    except Exception as e:
        print(Fore.RED + f"[!] Error sending TCP packet: {e}")

def send_udp_packet(src_ip, src_port, dst_ip, dst_port, payload):
    """
    Send a UDP packet using Scapy.
    """
    try:
        # Create the IP and UDP layers with source IP and port
        ip_layer = IP(src=src_ip, dst=dst_ip)
        udp_layer = UDP(sport=src_port, dport=dst_port)
        
        # Combine layers and the payload
        packet = ip_layer / udp_layer / payload
        
        print(Fore.GREEN + f"[*] Sending UDP packet from {src_ip}:{src_port} to {dst_ip}:{dst_port}")
        send(packet, verbose=False)
        print(Fore.GREEN + "[*] UDP packet sent successfully!")
    except Exception as e:
        print(Fore.RED + f"[!] Error sending UDP packet: {e}")

# Obfuscation techniques
def obfuscate_base64(payload):
    return base64.b64encode(payload).decode('utf-8')

def obfuscate_urlencode(payload):
    return urllib.parse.quote(payload)

def obfuscate_hex(payload):
    return payload.hex()

def obfuscate_xor(payload, key=0xAA):
    return bytes([b ^ key for b in payload])

def obfuscate_rot13(payload):
    return codecs.encode(payload.decode('utf-8'), 'rot_13').encode('utf-8')

def main():
    # Print the banner
    print_banner()

    print(Fore.YELLOW + "Choose packet type:")
    print(Fore.YELLOW + "1. TCP")
    print(Fore.YELLOW + "2. UDP")
    choice = input(Fore.CYAN + "Enter your choice (1 or 2): ")

    # Get user input for payload
    src_ip = input("Enter the source IP address: ")
    src_port = int(input("Enter the source port: "))
    dst_ip = input("Enter the target IP address: ")
    dst_port = int(input("Enter the target port: "))
    payload = input(Fore.CYAN + "Enter payload: ")
    payload = payload.encode("utf-8").decode("unicode_escape").encode("utf-8")
    
    # Asking for appropriate obfuscation technique
    print(Fore.YELLOW + "[>] What obfuscation would you want? [<]")
    print(Fore.YELLOW + "1. Base64")
    print(Fore.YELLOW + "2. URLEncode")
    print(Fore.YELLOW + "3. Hexadecimal")
    print(Fore.YELLOW + "4. XOR Encryption")
    print(Fore.YELLOW + "5. ROT-13 Encryption")
    print(Fore.YELLOW + "6. None")
    
    obfuscation_choice = input(Fore.CYAN + "Enter your choice (1-6): ")

    if obfuscation_choice == "1":
        payload = obfuscate_base64(payload)
    elif obfuscation_choice == "2":
        payload = obfuscate_urlencode(payload)
    elif obfuscation_choice == "3":
        payload = obfuscate_hex(payload)
    elif obfuscation_choice == "4":
        payload = obfuscate_xor(payload)
    elif obfuscation_choice == "5":
        payload = obfuscate_rot13(payload)
    elif obfuscation_choice == "6":
        print(Fore.GREEN + "[*] No obfuscation applied.")
    else:
        print(Fore.RED + "[!] Invalid choice! Exiting.")
        return

    print("Your crafted payload:")
    print(payload)

    # Send the packet based on user selection
    if choice == "1":
        send_tcp_packet(src_ip, src_port, dst_ip, dst_port, payload)
    elif choice == "2":
        send_udp_packet(src_ip, src_port, dst_ip, dst_port, payload)
    else:
        print(Fore.RED + "[!] Invalid choice! Exiting.")

if __name__ == "__main__":
    main()
