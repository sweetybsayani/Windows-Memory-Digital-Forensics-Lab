#!/usr/bin/env python
# ioc_extractor.py - IoC extraction for Windows Memory Forensics Lab

import os
import sys
import time
import colorama
from colorama import Fore, Back, Style
from tqdm import tqdm
import random
from prettytable import PrettyTable

# Initialize colorama
colorama.init()

# Set paths
EVIDENCE_PATH = os.path.join(os.getcwd(), "evidence")
REPORTS_PATH = os.path.join(os.getcwd(), "reports")

def print_banner():
    banner = """
 _____       _____   _______      _                  _             
|_   _|     / ____|  ____|\ \    / /                | |            
  | |  ___ / /   | |__    \ \  / /_ _ _ __ __ _  ___| |_ ___  _ __ 
  | | / _ \ |   |  __|    \ \/ / _` | '__/ _` |/ __| __/ _ \| '__|
 _| || (_) \ \___| |____    \  / (_| | | | (_| | (__| || (_) | |   
|_____\___/ \____|______|    \/ \__,_|_|  \__,_|\___|\__\___/|_|   
                                                                   
"""
    print(Fore.CYAN + banner + Style.RESET_ALL)
    print(Fore.YELLOW + "Dark Kittens Investigation - IoC Extractor" + Style.RESET_ALL)
    print(Fore.YELLOW + "=" * 80 + Style.RESET_ALL)
    print(Fore.WHITE + "Extracting Indicators of Compromise from memory dumps" + Style.RESET_ALL)
    print(Fore.YELLOW + "=" * 80 + Style.RESET_ALL + "\n")

def extract_iocs(memory_dump, pids):
    print(Fore.GREEN + f"[+] Extracting IoCs from memory dump: {memory_dump}" + Style.RESET_ALL)
    print(Fore.CYAN + f"[*] Target PIDs: {', '.join(pids)}" + Style.RESET_ALL)
    
    # Check if all PIDs exist in process list
    valid_pids = []
    process_names = {}
    
    try:
        process_file = os.path.join(EVIDENCE_PATH, "process_list.txt")
        with open(process_file, 'r') as f:
            lines = f.readlines()
            
        for line in lines:
            if line.startswith('#'):
                continue
                
            parts = line.strip().split(',')
            if len(parts) >= 5 and parts[0] in pids:
                valid_pids.append(parts[0])
                process_names[parts[0]] = parts[2]
    
    except Exception as e:
        print(Fore.RED + f"[!] Error reading process list: {e}" + Style.RESET_ALL)
        return
    
    # Check if any PIDs were not found
    if len(valid_pids) < len(pids):
        invalid_pids = [pid for pid in pids if pid not in valid_pids]
        print(Fore.RED + f"[!] Warning: PIDs not found in the memory dump: {', '.join(invalid_pids)}" + Style.RESET_ALL)
    
    if not valid_pids:
        print(Fore.RED + "[!] No valid PIDs to analyze!" + Style.RESET_ALL)
        return
    
    # Log the valid processes
    print(Fore.GREEN + "[+] Processes to analyze:" + Style.RESET_ALL)
    for pid in valid_pids:
        print(Fore.WHITE + f"    PID {pid}: {process_names[pid]}" + Style.RESET_ALL)
    
    print(Fore.CYAN + "\n[*] Scanning process memory for indicators..." + Style.RESET_ALL)
    
    for i in tqdm(range(100), desc="    Progress", ncols=80, bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"):
        time.sleep(random.uniform(0.01, 0.04))

    print(Fore.GREEN + "\n[+] Indicators of Compromise extracted:" + Style.RESET_ALL)
    
    # Files
    print(Fore.YELLOW + "\n1. File Indicators:" + Style.RESET_ALL)
    file_table = PrettyTable()
    file_table.field_names = ["File Path", "Associated PID", "Description", "Risk Level"]
    file_table.align = "l"
    
    file_table.add_row([
        "C:\\Windows\\System32\\svchost_update.exe", 
        "3244", 
        "Main malware executable masquerading as system file", 
        Fore.RED + "HIGH" + Style.RESET_ALL
    ])
    file_table.add_row([
        "C:\\Windows\\Temp\\svchost_update.exe", 
        "3724", 
        "Downloaded malware payload", 
        Fore.RED + "HIGH" + Style.RESET_ALL
    ])
    file_table.add_row([
        "C:\\ProgramData\\Microsoft\\Crypto\\keylog.dat", 
        "3244", 
        "Potential keylogger data file", 
        Fore.RED + "HIGH" + Style.RESET_ALL
    ])
    
    print(file_table)
    
    # Network Indicators
    print(Fore.YELLOW + "\n2. Network Indicators:" + Style.RESET_ALL)
    network_table = PrettyTable()
    network_table.field_names = ["Indicator", "Type", "Associated PID", "Description", "Risk Level"]
    network_table.align = "l"
    
    network_table.add_row([
        "darkittens.evil", 
        "Domain", 
        "3244, 3724", 
        "Command and control server domain", 
        Fore.RED + "HIGH" + Style.RESET_ALL
    ])
    network_table.add_row([
        "data-collect.darkittens.evil", 
        "Domain", 
        "3244", 
        "Data exfiltration server domain", 
        Fore.RED + "HIGH" + Style.RESET_ALL
    ])
    network_table.add_row([
        "185.73.23.4", 
        "IP Address", 
        "3244", 
        "Command and control server IP", 
        Fore.RED + "HIGH" + Style.RESET_ALL
    ])
    network_table.add_row([
        "23.81.246.187", 
        "IP Address", 
        "3244", 
        "Data exfiltration server IP", 
        Fore.RED + "HIGH" + Style.RESET_ALL
    ])
    network_table.add_row([
        "POST /upload.php?id=GLB-", 
        "URL Pattern", 
        "3244", 
        "Data exfiltration endpoint", 
        Fore.RED + "HIGH" + Style.RESET_ALL
    ])
    network_table.add_row([
        "https://darkittens.evil/c2/getpayload", 
        "URL", 
        "3724", 
        "Malware download URL", 
        Fore.RED + "HIGH" + Style.RESET_ALL
    ])
    
    print(network_table)
    
    # Registry Indicators
    print(Fore.YELLOW + "\n3. Registry Indicators:" + Style.RESET_ALL)
    registry_table = PrettyTable()
    registry_table.field_names = ["Registry Key/Value", "Associated PID", "Description", "Risk Level"]
    registry_table.align = "l"
    
    registry_table.add_row([
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemServiceManager", 
        "3244", 
        "Persistence mechanism - startup registry key", 
        Fore.RED + "HIGH" + Style.RESET_ALL
    ])
    
    print(registry_table)
    
    # Other Indicators
    print(Fore.YELLOW + "\n4. Other Indicators:" + Style.RESET_ALL)
    other_table = PrettyTable()
    other_table.field_names = ["Indicator", "Type", "Associated PID", "Description", "Risk Level"]
    other_table.align = "l"
    
    other_table.add_row([
        "D@rkK!tt3nsRul3Th3W0rld", 
        "Encryption Key", 
        "3244", 
        "Encryption key used for data exfiltration", 
        Fore.RED + "HIGH" + Style.RESET_ALL
    ])
    other_table.add_row([
        "DK_Global_Control", 
        "Mutex", 
        "3244", 
        "Mutex used to prevent multiple instances of malware", 
        Fore.RED + "HIGH" + Style.RESET_ALL
    ])
    other_table.add_row([
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", 
        "User-Agent", 
        "3244", 
        "Hardcoded user-agent string used in C2 communication", 
        Fore.YELLOW + "MEDIUM" + Style.RESET_ALL
    ])
    
    print(other_table)
    
    # Create IoC file
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    ioc_file = os.path.join(os.getcwd(), "workdir", f"ioc_list_{timestamp}.txt")
    
    with open(ioc_file, "w") as f:
        f.write("# Dark Kittens Investigation - Indicators of Compromise\n")
        f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Memory Dump: {memory_dump}\n")
        f.write(f"# Analyzed PIDs: {', '.join(valid_pids)}\n\n")
        
        f.write("## File Indicators\n")
        f.write("C:\\Windows\\System32\\svchost_update.exe\n")
        f.write("C:\\Windows\\Temp\\svchost_update.exe\n")
        f.write("C:\\ProgramData\\Microsoft\\Crypto\\keylog.dat\n\n")
        
        f.write("## Network Indicators\n")
        f.write("darkittens.evil\n")
        f.write("data-collect.darkittens.evil\n")
        f.write("185.73.23.4\n")
        f.write("23.81.246.187\n")
        f.write("POST /upload.php?id=GLB-\n")
        f.write("https://darkittens.evil/c2/getpayload\n\n")
        
        f.write("## Registry Indicators\n")
        f.write("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemServiceManager\n\n")
        
        f.write("## Other Indicators\n")
        f.write("D@rkK!tt3nsRul3Th3W0rld\n")
        f.write("DK_Global_Control\n")
        f.write("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\n")
    
    print(Fore.GREEN + f"\n[+] IoC list saved to: {ioc_file}" + Style.RESET_ALL)
    
    # MITRE ATT&CK Mapping
    print(Fore.YELLOW + "\n5. MITRE ATT&CK Techniques Identified:" + Style.RESET_ALL)
    mitre_table = PrettyTable()
    mitre_table.field_names = ["Technique ID", "Name", "Description"]
    mitre_table.align = "l"
    
    mitre_table.add_row([
        "T1036.005", 
        "Masquerading: Match Legitimate Name or Location", 
        "Malware masquerading as svchost.exe with a slight name modification"
    ])
    mitre_table.add_row([
        "T1059.001", 
        "Command and Scripting Interpreter: PowerShell", 
        "Use of PowerShell for downloading payloads and execution"
    ])
    mitre_table.add_row([
        "T1140", 
        "Deobfuscate/Decode Files or Information", 
        "Use of Base64 encoding to obfuscate PowerShell commands"
    ])
    mitre_table.add_row([
        "T1547.001", 
        "Boot or Logon Autostart Execution: Registry Run Keys", 
        "Use of registry run key for persistence"
    ])
    mitre_table.add_row([
        "T1071.001", 
        "Application Layer Protocol: Web Protocols", 
        "Use of HTTPS for command and control communications"
    ])
    mitre_table.add_row([
        "T1020", 
        "Automated Exfiltration", 
        "Automatic exfiltration of targeted documents"
    ])
    
    print(mitre_table)
    
    # Next steps
    print(Fore.YELLOW + "\nNext Steps:" + Style.RESET_ALL)
    print(Fore.WHITE + "1. Run 'python report_generator.py' to create your final report with the collected evidence" + Style.RESET_ALL)
    print(Fore.WHITE + "2. Use the extracted IoCs to scan other systems in the network for potential compromise" + Style.RESET_ALL)
    print(Fore.WHITE + "3. Implement blocking rules for the identified malicious domains and IPs" + Style.RESET_ALL)

# Main function
def main():
    print_banner()
    
    # Check command line arguments
    if len(sys.argv) < 3:
        print(Fore.RED + "[!] Please specify a memory dump file and at least one PID!" + Style.RESET_ALL)
        print(Fore.WHITE + "Usage: python ioc_extractor.py <memory_dump_file> <PID1> [PID2] [PID3] ..." + Style.RESET_ALL)
        print(Fore.WHITE + "Example: python ioc_extractor.py globomantics_workstation1.raw 3244 3536 3724" + Style.RESET_ALL)
        sys.exit(1)
    
    memory_dump = sys.argv[1]
    pids = sys.argv[2:]
    
    if not os.path.exists(EVIDENCE_PATH):
        print(Fore.RED + "[!] Evidence directory not found!" + Style.RESET_ALL)
        print(Fore.RED + "[!] Please run setup.py first to configure the lab environment." + Style.RESET_ALL)
        sys.exit(1)
    
    try:
        # Extract IoCs from the memory dump
        extract_iocs(memory_dump, pids)
        
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Extraction cancelled by user!" + Style.RESET_ALL)
        sys.exit(1)

if __name__ == "__main__":
    main()
