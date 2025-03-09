import os
import subprocess
import pyfiglet
from colorama import Fore, Style, init

# Initialize colorama
init()

def display_banner():
    banner = pyfiglet.figlet_format("Evil Payload Crafter")
    print(Fore.RED + banner + Style.RESET_ALL)
    print(Fore.YELLOW + "[!] A Tool to Craft and Obfuscate Payloads" + Style.RESET_ALL)

def show_menu():
    print(Fore.CYAN + "\nSelect a tool to execute:" + Style.RESET_ALL)
    print("1. SQL Payload Crafter")
    print("2. SMTP Payload Crafter")
    print("3. DNS Payload Crafter")
    print("4. FTP Payload Crafter")
    print("5. HTTP Payload Crafter")
    print("6. Backdoor DDoS Crafter")
    print("7. Network Mapping Tool")
    print("8. Telnet Payload Crafter")
    print("9. Exit")

def execute_tool(tool_script):
    try:
        print(Fore.GREEN + f"\n[+] Executing {tool_script}..." + Style.RESET_ALL)
        # Use Python to run the selected tool
        subprocess.run(["python3", tool_script])
    except Exception as e:
        print(Fore.RED + f"[-] Error executing {tool_script}: {e}" + Style.RESET_ALL)

def main():
    display_banner()

    scripts = [
        "sql.py",
        "smtp.py",
        "dns.py",
        "ftp.py",
        "http.py",
        "backdoor_ddos.py",
        "nmapping.py",
        "telnet.py"
    ]

    while True:
        show_menu()
        choice = input(Fore.MAGENTA + "\nEnter your choice (1-9): " + Style.RESET_ALL)

        if choice.isdigit() and 1 <= int(choice) <= 8:
            tool_script = scripts[int(choice) - 1]
            if os.path.exists(tool_script):
                execute_tool(tool_script)
            else:
                print(Fore.RED + f"[-] Script {tool_script} not found!" + Style.RESET_ALL)
        elif choice == "9":
            print(Fore.YELLOW + "\n[!] Exiting Evil Payload Crafter. Goodbye!" + Style.RESET_ALL)
            break
        else:
            print(Fore.RED + "[-] Invalid choice. Please select a valid option." + Style.RESET_ALL)

if __name__ == "__main__":
    main()
