import subprocess
import sys
import pyfiglet
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def print_banner():
    """
    Prints a banner for the script using pyfiglet and colorama for decoration.
    """
    banner = pyfiglet.figlet_format("Nmapping Tools")
    print(Fore.GREEN + banner)
    print(Fore.YELLOW + "Welcome to the Nmap Scanner Tool!")
    print(Fore.CYAN + "Use this tool to explore various Nmap techniques!\n")

def run_nmap_command(command):
    """
    Executes the Nmap command using subprocess.
    """
    try:
        print(Fore.BLUE + f"[*] Executing: {command}")
        subprocess.run(command, shell=True, check=True)
        print(Fore.GREEN + "[*] Scan completed successfully!")
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"[!] Error: {e}")
        sys.exit(1)

def decoy_scan():
    """
    Decoy Scan: Sending Packets from Multiple IP Addresses.
    """
    print(Fore.MAGENTA + "\nDecoy Scan: Sending packets from multiple IP addresses.")
    decoy_ips = input("Enter comma-separated list of decoy IPs (e.g., 192.168.1.1,192.168.1.2): ")
    target_ip = input("Enter target IP address: ")
    command = f"nmap -D {decoy_ips} {target_ip}"
    run_nmap_command(command)

def fragment_packets():
    """
    Fragment Packets: Sending 1000 Pieces of Packets.
    """
    print(Fore.MAGENTA + "\nFragment Packets: Sending 1000 pieces of packets.")
    mtu = input("Enter fragment size (e.g., 128, 256): ")
    target_ip = input("Enter target IP address: ")
    command = f"nmap --mtu {mtu} {target_ip}"
    run_nmap_command(command)

def mac_address_spoofing():
    """
    MAC Address Spoofing: Sending Packets with a Forged MAC Address.
    """
    print(Fore.MAGENTA + "\nMAC Address Spoofing: Sending packets with a forged MAC address.")
    mac_address = input("Enter the spoofed MAC address: ")
    target_ip = input("Enter target IP address: ")
    command = f"nmap --spoof-mac {mac_address} {target_ip}"
    run_nmap_command(command)

def source_port_manipulation():
    """
    Source Port Manipulation: Specifying the Source Port of Packets.
    """
    print(Fore.MAGENTA + "\nSource Port Manipulation: Specifying the source port of packets.")
    port = input("Enter the source port (e.g., 53, 80): ")
    target_ip = input("Enter target IP address: ")
    command = f"nmap --source-port {port} {target_ip}"
    run_nmap_command(command)

def ip_spoofing():
    """
    IP Spoofing: Sending Packets from a Forged IP Address.
    """
    print(Fore.MAGENTA + "\nIP Spoofing: Sending packets from a forged IP address.")
    spoofed_ip = input("Enter the spoofed IP address: ")
    target_ip = input("Enter target IP address: ")
    command = f"nmap -S {spoofed_ip} {target_ip}"
    run_nmap_command(command)

def firewalk():
    """
    Firewalk: Determining Packet Filter Rules. 
    Firewalk is used to determine whether a given packet filter rule
    is blocking traffic destined for a specific port.
    """
    print(Fore.MAGENTA + "\nFirewalk: Determining packet filter rules.")
    ttl = input("Enter max TTL value: ")
    target_ip = input("Enter target IP address: ")
    command = f"nmap -sA --ttl {ttl} {target_ip}"
    run_nmap_command(command)

def zombie_scan():
    """
    Zombie Scan: Scanning from a “Zombie” Host.
    """
    print(Fore.MAGENTA + "\nZombie Scan: Scanning from a 'Zombie' host.")
    zombie_host_ip = input("Enter zombie host IP address: ")
    target_ip = input("Enter target IP address: ")
    command = f"nmap -Pn -sI {zombie_host_ip} {target_ip}"
    run_nmap_command(command)

def bad_checksum():
    """
    Bad Checksum: Sending Packets with Incorrect Checksums.
    """
    print(Fore.MAGENTA + "\nBad Checksum: Sending packets with incorrect checksums.")
    target_ip = input("Enter target IP address: ")
    command = f"nmap --badsum {target_ip}"
    run_nmap_command(command)

def obfuscation():
    """
    Obfuscation: Modifying Nmap Scan to Evade Detection.
    """
    print(Fore.MAGENTA + "\nObfuscation: Modifying Nmap scan to evade detection.")
    target_ip = input("Enter target IP address: ")
    command = f"nmap --randomize-hosts -sS {target_ip}"
    run_nmap_command(command)

def protocol_violations():
    """
    Protocol Violations: Sending Non-Standard Packets.
    """
    print(Fore.MAGENTA + "\nProtocol Violations: Sending non-standard packets.")
    target_ip = input("Enter target IP address: ")
    command = f"nmap --badsum {target_ip}"
    run_nmap_command(command)

def ttl_manipulation():
    """
    TTL Manipulation: Modifying TTL Values in IP Packets.
    """
    print(Fore.MAGENTA + "\nTTL Manipulation: Modifying TTL values in IP packets.")
    ttl_value = input("Enter TTL value: ")
    target_ip = input("Enter target IP address: ")
    command = f"nmap --ttl {ttl_value} {target_ip}"
    run_nmap_command(command)

def main():
    """
    Main function to present options to the user and execute the corresponding Nmap scan.
    """
    print_banner()

    print(Fore.YELLOW + "Select a Nmap scan technique:")
    print(Fore.CYAN + "1. Decoy Scan")
    print(Fore.CYAN + "2. Fragment Packets")
    print(Fore.CYAN + "3. MAC Address Spoofing")
    print(Fore.CYAN + "4. Source Port Manipulation")
    print(Fore.CYAN + "5. IP Spoofing")
    print(Fore.CYAN + "6. Firewalk")
    print(Fore.CYAN + "7. Zombie Scan")
    print(Fore.CYAN + "8. Bad Checksum")
    print(Fore.CYAN + "9. Obfuscation")
    print(Fore.CYAN + "10. Protocol Violations")
    print(Fore.CYAN + "11. TTL Manipulation")
    print(Fore.CYAN + "12. Return to Main Menu")
    
    choice = input(Fore.YELLOW + "Enter your choice (1-12): ")

    if choice == "1":
        decoy_scan()
    elif choice == "2":
        fragment_packets()
    elif choice == "3":
        mac_address_spoofing()
    elif choice == "4":
        source_port_manipulation()
    elif choice == "5":
        ip_spoofing()
    elif choice == "6":
        firewalk()
    elif choice == "7":
        zombie_scan()
    elif choice == "8":
        bad_checksum()
    elif choice == "9":
        obfuscation()
    elif choice == "10":
        protocol_violations()
    elif choice == "11":
        ttl_manipulation()
    elif choice == "12":
        print(Fore.GREEN + "Returning to Main Menu.")
    else:
        print(Fore.RED + "[!] Invalid choice! Exiting.")

if __name__ == "__main__":
    main()
