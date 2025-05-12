# Windows-Memory-Digital-Forensics-Lab

## Overview
This lab provides hands-on experience with memory forensics to detect Dark Kittens malware in a compromised Windows system. Learn how to analyze memory dumps to identify malicious artifacts, processes, and network connections using industry-standard tools.

## Lab Scenario

Globomantics security team has detected unusual activity on one of their critical workstations. The system appears to be communicating with suspicious external IPs, but traditional antivirus tools haven't detected any malware. You've been called in to analyze a memory dump from the compromised machine to identify potential Dark Kittens malware, establish persistence mechanisms, and determine what data may have been exfiltrated.

## Learning Objectives

- Set up a memory forensics environment on Windows
- Use Volatility to analyze Windows memory dumps
- Identify suspicious processes, network connections, and malware artifacts
- Extract forensic evidence to determine attack vectors
- Document findings in a professional forensic report

## Lab Setup Instructions 

1. Clone the repository to your local machine:
   ```
   git clone https://github.com/sweetybsayani/Windows-Memory-Forensics-Lab.git
   ```

2. Navigate to the lab directory:
   ```
   cd Windows-Memory-Forensics-Lab
   ```

3. Run the environment setup script from Command Prompt as Administrator:
   ```
   python setup.py
   ```
   This script will:
   - Download and install Python if not already installed
   - Install required Python packages
   - Download Volatility framework
   - Download sample memory dumps
   - Create working directories
   - Verify all components are properly configured

## Lab Tasks & Execution Workflow

### Task 1: Analyze the Memory Dump

1. Open Command Prompt (CMD) as Administrator
2. Navigate to the lab directory:
   ```
   cd C:\path\to\Windows-Memory-Forensics-Lab
   ```
3. Run the memory analysis script:
   ```
   python analyze_memory.py
   ```
4. When prompted, select the memory dump to analyze (option 1 for workstation dump)
- Choose option 1 (globomantics_workstation1.raw)
- Review the initial analysis results

### Task 2: Process Identification & Analysis

1. In Command Prompt, run the process scanner:
   ```
   python process_scanner.py globomantics_workstation1.raw
   ```
2. Review the output to identify suspicious processes
3. Note the PIDs of suspicious processes (3244, 3536, 3724)

### Task 3: Evidence Collection & Analysis

1. For each suspicious PID identified, run the evidence collector:
   ```
   python evidence_collector.py globomantics_workstation1.raw 3244
   ```
   ```
   python evidence_collector.py globomantics_workstation1.raw 3536
   ```
   ```
   python evidence_collector.py globomantics_workstation1.raw 3724
   ```
2. Analyze the extracted artifacts for each process
- Analyze command lines, network connections, and memory strings
- Look for malicious behaviors in each process

### Task 4: Malware Indicators Extraction

1. Run the IOC extractor on all suspicious processes:
   ```
   python ioc_extractor.py globomantics_workstation1.raw 3244 3536 3724
   ```
2. Review the extracted Indicators of Compromise (IOCs)
3. Note how they align with the MITRE ATT&CK framework

### Task 5: Generate Forensic Report

1. Run the report generator:
   ```
   python report_generator.py
   ```
2. When prompted, enter:
   - Case title (e.g., "Dark Kittens Malware Analysis")
   - Your name as the investigator
   - PIDs of all suspicious processes identified (3244, 3536, 3724)
3. Review the generated HTML report in your browser
4. Answer these reflection questions:
   - What additional analysis techniques could be applied to this investigation?
   - How would you improve the response to this type of incident in a real environment?
   - What preventive measures could have detected or blocked this attack earlier?

The lab consists of the following key components:

- `setup.py`: Automates the lab environment setup
- `analyze_memory.py`: Identifies basic information from the memory dump
- `process_scanner.py`: Scans for and identifies suspicious processes
- `evidence_collector.py`: Extracts detailed evidence from specific processes
- `ioc_extractor.py`: Identifies indicators of compromise
- `report_generator.py`: Creates a comprehensive forensic report

## Hints & Tips

- Look for processes with unusual names or those that appear legitimate but are running from unexpected locations
- Pay attention to parent-child process relationships
- Network connections to unusual IPs/domains are strong indicators of compromise
- Some malware may inject code into legitimate processes
- Check for suspicious registry entries that may indicate persistence mechanisms
- Base64-encoded PowerShell commands often indicate malicious activity

## Completion Criteria

You have successfully completed this lab when you can:
1. Identify all suspicious processes related to the Dark Kittens intrusion
2. Extract key IOCs from the memory dump
3. Identify the persistence mechanism used by the malware
4. Determine what data was targeted for exfiltration
5. Generate a complete forensic report documenting your findings

## Troubleshooting

If you encounter issues:

- Ensure you're running scripts from CMD with Administrator privileges
- Verify Python is in your PATH environment variable
- If any script fails with an error, check the error message and try running it again
- Make sure all directories (tools, evidence, reports, etc.) exist before running the scripts
- If a script hangs, you can press Ctrl+C to cancel it and try again

## References

- Volatility Documentation: https://github.com/volatilityfoundation/volatility/wiki
- SANS Memory Forensics Cheat Sheet: https://www.sans.org/blog/memory-forensics-cheat-sheet/
- Windows Registry Forensics: https://www.sciencedirect.com/topics/computer-science/windows-registry-forensics
- MITRE ATT&CK Framework: https://attack.mitre.org/
