import base64
import urllib.parse
import random
import socket
from colorama import Fore, Style, init
import pyfiglet

# Initialize colorama
init(autoreset=True)

def display_banner():
    banner = pyfiglet.figlet_format("SQL Packet Crafter")
    print(Fore.CYAN + banner)
    print(Fore.YELLOW + "[>] Welcome to the SQL Packet Crafter! [<]")

def encode_base64(payload):
    return base64.b64encode(payload.encode()).decode()

def encode_url(payload):
    return urllib.parse.quote(payload)

def encode_hex(payload):
    return ''.join(format(ord(char), '02x') for char in payload)

def xor_encrypt(payload, key):
    return ''.join(chr(ord(c) ^ key) for c in payload)

def generate_obfuscation(payload, choice):
    if choice == 1:
        print(Fore.GREEN + "Encoding Payload in Base64!")
        return encode_base64(payload)
    elif choice == 2:
        print(Fore.GREEN + "Encoding Payload in URL Encoding!")
        return encode_url(payload)
    elif choice == 3:
        print(Fore.GREEN + "Encoding Payload in Hexadecimal!")
        return encode_hex(payload)
    elif choice == 4:
        key = random.randint(1, 255)  # Random XOR key
        print(Fore.GREEN + f"Encrypting Payload using XOR Encryption with key: {key}")
        encrypted = xor_encrypt(payload, key)
        return f"Key={key};Encrypted={encode_base64(encrypted)}"
    elif choice == 5:
        print(Fore.GREEN + "Encrypting Payload using ROT-13!")
        # ROT13 implemented using encode/decode
        return payload.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
    elif choice == 6:
        print(Fore.GREEN + "No obfuscation selected.")
        return payload
    else:
        print(Fore.RED + "Invalid choice. No obfuscation applied.")
        return payload

def send_payload(target_ip, target_port, payload):
    try:
        print(Fore.CYAN + f"Connecting to {target_ip} on port {target_port}...")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((target_ip, target_port))
            sock.sendall(payload.encode())  # Send the payload as bytes
            print(Fore.GREEN + "Payload sent successfully!")
    except Exception as e:
        print(Fore.RED + f"Error sending payload: {e}")

def main():
    display_banner()

    # Target Information
    target_ip = input(Fore.YELLOW + "Enter the target IP address: ").strip()
    target_port = int(input(Fore.YELLOW + "Enter the target port (default is 3306 for MySQL): ").strip())

    # Payload Input
    print(Fore.MAGENTA + "\nEnter your SQL query payload (type 'EOF' on a new line to finish):")
    payload_lines = []
    while True:
        line = input()
        if line.strip().upper() == "EOF":
            break
        payload_lines.append(line)
    payload = "\n".join(payload_lines)

    # Obfuscation Menu
    print(Fore.MAGENTA + "\n[>] What Obfuscation would you want? [<]")
    print(Fore.CYAN + "1. Base64")
    print(Fore.CYAN + "2. URLEncode")
    print(Fore.CYAN + "3. Hexadecimal")
    print(Fore.CYAN + "4. XOR Encryption")
    print(Fore.CYAN + "5. ROT-13 Encryption")
    print(Fore.CYAN + "6. None")
    choice = int(input(Fore.YELLOW + "Enter the number corresponding to your choice: "))

    # Obfuscation Process
    obfuscated_payload = generate_obfuscation(payload, choice)

    print(Fore.LIGHTYELLOW_EX + "\nYour crafted payload:")
    print(Fore.LIGHTBLUE_EX + obfuscated_payload)

    # Sending Payload
    send_payload(target_ip, target_port, obfuscated_payload)

if __name__ == "__main__":
    main()
