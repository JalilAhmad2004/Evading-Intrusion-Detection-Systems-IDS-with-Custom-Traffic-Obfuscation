from scapy.all import IP, TCP, send
import base64
import urllib.parse
import pyfiglet
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Display banner using pyfiglet
def print_banner():
    banner = pyfiglet.figlet_format("Telnet Client")
    print(Fore.CYAN + banner)

def obfuscate_payload(payload, method):
    if method == "Base64":
        return base64.b64encode(payload.encode()).decode()
    elif method == "URLEncode":
        return urllib.parse.quote(payload)
    elif method == "Hexadecimal":
        return ''.join(f"{byte:02x}" for byte in payload.encode())
    elif method == "None":
        return payload
    else:
        raise ValueError("Unsupported obfuscation method!")

def send_telnet_packet(source_ip, source_port, host, port, command, obfuscation):
    try:
        obfuscated_command = obfuscate_payload(command, obfuscation)
        print(Fore.YELLOW + f"[>] Sending obfuscated command: {obfuscated_command}")

        # Build Scapy packet
        packet = IP(src=source_ip, dst=host) / TCP(sport=source_port, dport=port, flags='PA') / obfuscated_command
        send(packet, verbose=0)

        print(Fore.GREEN + f"[+] Packet sent from {source_ip}:{source_port} to {host}:{port}")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}")

if __name__ == "__main__":
    print_banner()
    
    # Collect target details
    target_ip = input(Fore.CYAN + "Enter the target Telnet server IP: ")
    target_port = int(input(Fore.CYAN + "Enter the target Telnet port (default is 23): ") or 23)
    
    # Collect source details
    source_ip = input(Fore.CYAN + "Enter the source IP (use your local IP or spoof): ")
    source_port = int(input(Fore.CYAN + "Enter the source port (default is 12345): ") or 12345)
    
    # Enter commands
    print(Fore.YELLOW + "[+] Enter commands to send (type 'EOF' to finish):")
    commands = []
    while True:
        command = input(Fore.CYAN + "> ")
        if command.strip().upper() == "EOF":
            break
        commands.append(command)

    # Select obfuscation method
    print(Fore.YELLOW + "[+] Select obfuscation method:")
    print(Fore.YELLOW + "1. Base64\n2. URLEncode\n3. Hexadecimal\n4. None")
    choice = input(Fore.CYAN + "Enter your choice: ")
    
    methods = {1: "Base64", 2: "URLEncode", 3: "Hexadecimal", 4: "None"}
    obfuscation = methods.get(int(choice), "None")
    
    # Send packets
    for command in commands:
        send_telnet_packet(source_ip, source_port, target_ip, target_port, command, obfuscation)


