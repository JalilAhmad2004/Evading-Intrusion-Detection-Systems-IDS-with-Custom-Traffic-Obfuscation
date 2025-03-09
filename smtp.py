import socket
import base64
import urllib.parse
import binascii
from colorama import Fore, Style, init
import pyfiglet

# Initialize colorama
init(autoreset=True)

def display_banner():
    banner = pyfiglet.figlet_format("SMTP Packet Crafter")
    print(Fore.CYAN + banner)
    print(Fore.YELLOW + "[>] Welcome to the SMTP Packet Crafter! [<]")

def obfuscate_payload(payload, method):
    if method == "1":  # Base64
        print(Fore.GREEN + "Applying Base64 Encoding!")
        return base64.b64encode(payload.encode()).decode()
    elif method == "2":  # URL Encoding
        print(Fore.GREEN + "Applying URL Encoding!")
        return urllib.parse.quote(payload)
    elif method == "3":  # Hexadecimal
        print(Fore.GREEN + "Applying Hexadecimal Encoding!")
        return binascii.hexlify(payload.encode()).decode()
    elif method == "4":  # XOR Encryption
        key = 0x5A  # Example XOR key
        print(Fore.GREEN + f"Applying XOR Encryption with key: {key}")
        return ''.join(chr(ord(char) ^ key) for char in payload)
    elif method == "5":  # ROT-13
        print(Fore.GREEN + "Applying ROT-13 Encryption!")
        return payload.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
        ))
    else:
        print(Fore.YELLOW + "No obfuscation selected.")
        return payload  # No obfuscation

def send_smtp_payload(target_ip, target_port, source_ip, source_port, payload):
    try:
        print(Fore.CYAN + f"Connecting to {target_ip} on port {target_port}...")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Bind to the specified source IP and port
            s.bind((source_ip, source_port))
            # Connect to the local proxy instead of the target directly
            proxy_ip = "127.0.0.1"  # Local proxy IP
            proxy_port = 25         # Local proxy port
            s.connect((proxy_ip, proxy_port))

            response = s.recv(1024)
            print(Fore.BLUE + f"Received: {response.decode()}")

            # SMTP handshake and payload delivery
            print(Fore.MAGENTA + "Sending HELO command...")
            s.sendall(b"HELO example.com\r\n")
            response = s.recv(1024)
            print(Fore.BLUE + f"Received: {response.decode()}")

            print(Fore.MAGENTA + "Sending crafted payload...")
            s.sendall(payload.encode() + b"\r\n")
            response = s.recv(1024)
            print(Fore.BLUE + f"Received: {response.decode()}")

            s.sendall(b"QUIT\r\n")
            print(Fore.GREEN + "Payload sent successfully.")
    except Exception as e:
        print(Fore.RED + f"Error sending payload: {e}")

def main():
    display_banner()

    # Gather source information
    source_ip = input(Fore.YELLOW + "Enter the source IP address: ").strip()
    source_port = input(Fore.YELLOW + "Enter the source port: ").strip()
    source_port = int(source_port)

    # Gather target information
    target_ip = input(Fore.YELLOW + "Enter the target IP address: ").strip()
    target_port = input(Fore.YELLOW + "Enter the target port (default is 25 for SMTP): ").strip()
    target_port = int(target_port) if target_port else 25

    # Enter payload
    print(Fore.MAGENTA + "\nEnter your SMTP payload (type 'EOF' on a new line to finish):")
    payload_lines = []
    while True:
        line = input()
        if line.upper() == "EOF":
            break
        payload_lines.append(line)
    payload = "\r\n".join(payload_lines)

    # Obfuscation options
    print(Fore.MAGENTA + "\n[>] What Obfuscation would you like? [<]")
    print(Fore.CYAN + "1. Base64\n2. URLEncode\n3. Hexadecimal\n4. XOR Encryption\n5. ROT-13 Encryption\n6. None")
    method = input(Fore.YELLOW + "Enter the number corresponding to your choice: ").strip()

    # Obfuscate payload
    crafted_payload = obfuscate_payload(payload, method)
    print(Fore.LIGHTYELLOW_EX + "\nYour crafted payload:")
    print(Fore.LIGHTBLUE_EX + crafted_payload)

    # Send payload
    send_smtp_payload(target_ip, target_port, source_ip, source_port, crafted_payload)

if __name__ == "__main__":
    main()

