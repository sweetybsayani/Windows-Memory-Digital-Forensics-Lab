#!/usr/bin/env python

import os
import sys
import time
import colorama
from colorama import Fore, Back, Style
from tqdm import tqdm
import random
from prettytable import PrettyTable

colorama.init()

EVIDENCE_PATH = os.path.join(os.getcwd(), "evidence")

def print_banner():
    banner = """
 _____                              _____                                 
|  __ \\                            / ____|                                
| |__) | __ ___   ___ ___  ___ ___| (___   ___ __ _ _ __  _ __   ___ _ __ 
|  ___/ '__/ _ \\ / __/ _ \\/ __/ __|___ \\ / __/ _` | '_ \\| '_ \\ / _ \\ '__|
| |   | | | (_) | (__|  __/\\__ \\__ \\___) | (_| (_| | | | | | | |  __/ |   
|_|   |_|  \\___/ \\___\\___||___/___/_____/ \\___\\__,_|_| |_|_| |_|\\___|_|   
                                                                          
"""
    print(Fore.CYAN + banner + Style.RESET_ALL)
    print(Fore.YELLOW + "Dark Kittens Investigation - Process Scanner" + Style.RESET_ALL)
    print(Fore.YELLOW + "=" * 80 + Style.RESET_ALL)
    print(Fore.WHITE + "Identifying suspicious processes in memory dumps" + Style.RESET_ALL)
    print(Fore.YELLOW + "=" * 80 + Style.RESET_ALL + "\n")

def scan_processes(memory_dump):
    print(Fore.GREEN + f"[+] Scanning processes in memory dump: {memory_dump}" + Style.RESET_ALL)
    
    print(Fore.CYAN + "[*] Running process scan..." + Style.RESET_ALL)
    
    for i in tqdm(range(100), desc="    Progress", ncols=80, bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"):
        time.sleep(random.uniform(0.01, 0.03))
    
    table = PrettyTable()
    table.field_names = ["PID", "PPID", "Process Name", "Path", "Created", "Status", "Risk Score"]
    table.align = "l"
    
    # Read the process list from the evidence file
    try:
        process_file = os.path.join(EVIDENCE_PATH, "process_list.txt")
        with open(process_file, 'r') as f:
            lines = f.readlines()
            
        for line in lines:
            if line.startswith('#'):
                continue
                
            parts = line.strip().split(',')
            if len(parts) >= 5:
                pid = parts[0]
                ppid = parts[1]
                name = parts[2]
                path = parts[3]
                created = parts[4]
                
                risk_score = 0
                status = "Normal"
                
                # Check for suspicious indicators
                if name == "svchost_update.exe":
                    risk_score = 9
                    status = Fore.RED + "SUSPICIOUS" + Style.RESET_ALL
                elif name == "powershell.exe" and ppid == "3536":
                    risk_score = 7
                    status = Fore.RED + "SUSPICIOUS" + Style.RESET_ALL
                elif name == "cmd.exe" and ppid == "3244":
                    risk_score = 6
                    status = Fore.RED + "SUSPICIOUS" + Style.RESET_ALL
                elif "svchost.exe" in name and ppid == "788":
                    risk_score = 1
                    status = Fore.GREEN + "NORMAL" + Style.RESET_ALL
                else:
                    risk_score = 0
                    status = Fore.GREEN + "NORMAL" + Style.RESET_ALL
                
                table.add_row([pid, ppid, name, path, created, status, risk_score])
    
    except Exception as e:
        print(Fore.RED + f"[!] Error reading process list: {e}" + Style.RESET_ALL)
        return
    
    # Print results
    print("\n" + Fore.GREEN + "[+] Process scan complete!" + Style.RESET_ALL)
    print(table)
    
    print(Fore.YELLOW + "\nSuspicious Processes Summary:" + Style.RESET_ALL)
    print(Fore.RED + "[!] PID 3244: svchost_update.exe - Unusual name for svchost process" + Style.RESET_ALL)
    print(Fore.RED + "[!] PID 3536: cmd.exe - Spawned by suspicious process" + Style.RESET_ALL)
    print(Fore.RED + "[!] PID 3724: powershell.exe - Potentially obfuscated command execution" + Style.RESET_ALL)
    
    print(Fore.YELLOW + "\nNetwork Connections for Suspicious Processes:" + Style.RESET_ALL)
    
    try:
        network_file = os.path.join(EVIDENCE_PATH, "network_connections.txt")
        with open(network_file, 'r') as f:
            lines = f.readlines()
        
        conn_table = PrettyTable()
        conn_table.field_names = ["PID", "Process", "Local Address", "Remote Address", "State", "Status"]
        conn_table.align = "l"
        
        for line in lines:
            if line.startswith('#'):
                continue
                
            parts = line.strip().split(',')
            if len(parts) >= 5:
                pid = parts[0]
                proc = parts[1]
                local = parts[2]
                remote = parts[3]
                state = parts[4]
                
                # Check if the process is suspicious
                if pid == "3244":  # svchost_update.exe
                    status = Fore.RED + "SUSPICIOUS" + Style.RESET_ALL
                    conn_table.add_row([pid, proc, local, remote, state, status])
        
        print(conn_table)
    
    except Exception as e:
        print(Fore.RED + f"[!] Error reading network connections: {e}" + Style.RESET_ALL)
    
    print(Fore.YELLOW + "\nNext Steps:" + Style.RESET_ALL)
    print(Fore.WHITE + "1. Run 'python evidence_collector.py globomantics_workstation1.raw 3244' to analyze the main suspicious process" + Style.RESET_ALL)
    print(Fore.WHITE + "2. Run 'python evidence_collector.py globomantics_workstation1.raw 3724' to analyze the PowerShell activity" + Style.RESET_ALL)
    print(Fore.WHITE + "3. Run 'python ioc_extractor.py globomantics_workstation1.raw 3244 3536 3724' to extract all IOCs" + Style.RESET_ALL)

# Main function
def main():
    print_banner()
    
    # Check cli arguments
    if len(sys.argv) < 2:
        print(Fore.RED + "[!] Please specify a memory dump file!" + Style.RESET_ALL)
        print(Fore.WHITE + "Usage: python process_scanner.py <memory_dump_file>" + Style.RESET_ALL)
        print(Fore.WHITE + "Example: python process_scanner.py globomantics_workstation1.raw" + Style.RESET_ALL)
        sys.exit(1)
    
    memory_dump = sys.argv[1]
    
    if not os.path.exists(EVIDENCE_PATH):
        print(Fore.RED + "[!] Evidence directory not found!" + Style.RESET_ALL)
        print(Fore.RED + "[!] Please run setup.py first to configure the lab environment." + Style.RESET_ALL)
        sys.exit(1)
    
    try:
        # Scan processes in the memory dump
        scan_processes(memory_dump)
        
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Scan cancelled by user!" + Style.RESET_ALL)
        sys.exit(1)

if __name__ == "__main__":
    main()
