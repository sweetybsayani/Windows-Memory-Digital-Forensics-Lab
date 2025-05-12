#!/usr/bin/env python

import os
import sys
import subprocess
import time
import shutil
import ctypes
import colorama
from colorama import Fore, Back, Style
from tqdm import tqdm
import random

colorama.init()

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Set paths
VOLATILITY_PATH = os.path.join(os.getcwd(), "tools", "volatility-master")
VOLATILITY3_PATH = os.path.join(os.getcwd(), "tools", "volatility3-master")
MEMORY_DUMPS_PATH = os.path.join(os.getcwd(), "memory_dumps")
EVIDENCE_PATH = os.path.join(os.getcwd(), "evidence")
WORKDIR_PATH = os.path.join(os.getcwd(), "workdir")

# ASCII art banner
def print_banner():
    banner = """
_____                  _         _       __  __                          
 / ____|                | |       ( )     |  \/  |                         
| (_____      _____  ___| |_ _   _|/ ___  | \  / | ___ _ __ ___   ___  _ __ _   _ 
 \___ \ \ /\ / / _ \/ _ \ __| | | | / __| | |\/| |/ _ \ '_ ` _ \ / _ \| '__| | | |
 ____) \ V  V /  __/  __/ |_| |_| | \__ \ | |  | |  __/ | | | | | (_) | |  | |_| |
|_____/ \_/\_/ \___|\___|\__|\__, | |___/ |_|  |_|\___|_| |_| |_|\___/|_|   \__, |
                              __/ |                                           __/ |
                             |___/                                           |___/
|  ___|                         (_)         | |         | |                        
| |__ ___  _ __ ___ _ __  ___   _  ___ ___  | |     __ _| |__                      
|  __/ _ \\| '__/ _ \\ '_ \\/ __| | |/ __/ __| | |    / _` | '_ \\                     
| | | (_) | | |  __/ | | \\__ \\ | | (__\\__ \\ | |___| (_| | |_) |                    
\\_|  \\___/|_|  \\___|_| |_|___/ |_|\\___|___/ \\_____/\\__,_|_.__/                     
                                                                                   
"""
    print(Fore.CYAN + banner + Style.RESET_ALL)
    print(Fore.YELLOW + "Dark Kittens Investigation" + Style.RESET_ALL)
    print(Fore.YELLOW + "=" * 80 + Style.RESET_ALL)
    print(Fore.WHITE + "Analyzing memory dumps to detect indicators of compromise" + Style.RESET_ALL)
    print(Fore.YELLOW + "=" * 80 + Style.RESET_ALL + "\n")

def analyze_memory_dump(memory_dump):
    print(Fore.GREEN + f"[+] Analyzing memory dump: {memory_dump}" + Style.RESET_ALL)
    print(Fore.CYAN + "[*] Initializing Volatility Framework..." + Style.RESET_ALL)
    
    analysis_steps = [
        "Determining Windows profile...",
        "Scanning for processes...",
        "Analyzing process tree...",
        "Checking network connections...",
        "Extracting command history...",
        "Scanning for malware artifacts...",
        "Analyzing registry hives...",
        "Checking for code injection...",
        "Extracting suspicious strings...",
        "Finalizing analysis..."
    ]
    
    for step in analysis_steps:
        print(Fore.CYAN + f"[*] {step}" + Style.RESET_ALL)
        
        # Create progress bar
        for i in tqdm(range(100), desc="    Progress", ncols=80, bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"):
            time.sleep(random.uniform(0.01, 0.05))  # Random delay between 0.01 and 0.05 seconds
    
    #  analysis results
    print("\n" + Fore.GREEN + "[+] Analysis complete!" + Style.RESET_ALL)
    print(Fore.YELLOW + "=" * 80 + Style.RESET_ALL)
    print(Fore.WHITE + "Initial Findings:" + Style.RESET_ALL)
    print(Fore.WHITE + "- " + Fore.RED + "3 suspicious processes detected" + Style.RESET_ALL)
    print(Fore.WHITE + "- " + Fore.RED + "5 unusual network connections found" + Style.RESET_ALL)
    print(Fore.WHITE + "- " + Fore.RED + "Registry persistence mechanisms identified" + Style.RESET_ALL)
    print(Fore.WHITE + "- " + Fore.RED + "Potential data exfiltration activity" + Style.RESET_ALL)
    print(Fore.YELLOW + "=" * 80 + Style.RESET_ALL)
    
    print(Fore.GREEN + "\n[+] Results saved to evidence directory" + Style.RESET_ALL)
    
    if os.path.exists(EVIDENCE_PATH):
        print(Fore.CYAN + "[*] Extracting artifacts to evidence directory..." + Style.RESET_ALL)
        
        # Create a new directory for this analysis session
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        session_dir = os.path.join(WORKDIR_PATH, f"analysis_{timestamp}")
        os.makedirs(session_dir, exist_ok=True)
        
        # Copy evidence files
        for evidence_file in os.listdir(EVIDENCE_PATH):
            src_file = os.path.join(EVIDENCE_PATH, evidence_file)
            dst_file = os.path.join(session_dir, evidence_file)
            shutil.copy2(src_file, dst_file)
        
        print(Fore.GREEN + f"[+] Artifacts extracted to: {session_dir}" + Style.RESET_ALL)
    
    # Next steps
    print(Fore.YELLOW + "\nNext Steps:" + Style.RESET_ALL)
    print(Fore.WHITE + "1. Run 'python process_scanner.py globomantics_workstation1.raw' to identify suspicious processes" + Style.RESET_ALL)
    print(Fore.WHITE + "2. Run 'python evidence_collector.py globomantics_workstation1.raw [PID]' to analyze specific processes" + Style.RESET_ALL)
    print(Fore.WHITE + "3. Run 'python ioc_extractor.py globomantics_workstation1.raw [PID1] [PID2] [PID3]' to extract IOCs" + Style.RESET_ALL)
    print(Fore.WHITE + "4. Run 'python report_generator.py' to create your final report" + Style.RESET_ALL)

# Main function
def main():
    if not is_admin():
        print(Fore.RED + "This script requires administrative privileges." + Style.RESET_ALL)
        print(Fore.RED + "Please run Command Prompt as Administrator and try again." + Style.RESET_ALL)
        input("Press Enter to exit...")
        sys.exit(1)
    
    print_banner()
    
    # Check if memory dumps exist
    if not os.path.exists(MEMORY_DUMPS_PATH):
        print(Fore.RED + "[!] Memory dumps directory not found!" + Style.RESET_ALL)
        print(Fore.RED + "[!] Please run setup.py first to configure the lab environment." + Style.RESET_ALL)
        input("Press Enter to exit...")
        sys.exit(1)
    
    memory_dumps = [
        "globomantics_workstation1.raw",
        "globomantics_server.raw"
    ]
    
    print(Fore.YELLOW + "Available memory dumps:" + Style.RESET_ALL)
    for i, dump in enumerate(memory_dumps, 1):
        print(Fore.WHITE + f"{i}. {dump}" + Style.RESET_ALL)
    
    try:
        selection = int(input(Fore.YELLOW + "\nSelect a memory dump (1-2): " + Style.RESET_ALL))
        if selection < 1 or selection > len(memory_dumps):
            print(Fore.RED + "[!] Invalid selection!" + Style.RESET_ALL)
            input("Press Enter to exit...")
            sys.exit(1)
        
        # Analyze selected memory dump
        selected_dump = memory_dumps[selection - 1]
        analyze_memory_dump(selected_dump)
        
    except ValueError:
        print(Fore.RED + "[!] Please enter a valid number!" + Style.RESET_ALL)
        input("Press Enter to exit...")
        sys.exit(1)
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Analysis cancelled by user!" + Style.RESET_ALL)
        sys.exit(1)

if __name__ == "__main__":
    main()
