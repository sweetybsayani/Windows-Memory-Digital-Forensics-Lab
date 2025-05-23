## Introduction

This Windows Memory Forensics Lab provides a simulated environment for security professionals and students to practice memory forensics techniques against a realistic attack scenario. The lab features the Dark Kittens threat group, a fictional APT targeting Globomantics' critical infrastructure.

Through a series of guided exercises, you'll learn to:
- Analyze memory dumps using forensic techniques
- Identify malicious processes and network connections
- Extract indicators of compromise
- Investigate persistence mechanisms
- Document findings in a professional forensic report

## Lab Setup Instructions 

1. Clone the repository to your local machine:
   ```
   git clone https://github.com/sweetybsayani/Windows-Memory-Digital-Forensics-Lab.git

   ```

2. Navigate to the lab directory:
   ```
   cd Windows-Memory-Digital-Forensics-Lab
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

1. Run the memory analysis script:
   ```
   python analyze_memory.py
   ```
2. When prompted, select the memory dump to analyze (option 1 for workstation dump)
- Choose option 1 or 2 (globomantics_workstation1.raw)
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

- Ensure you're running scripts from CMD with Administrator privileges or use sudo
- Verify Python is installed and is in your PATH environment variable
- Module Import Errors: Run `pip install -r requirements.txt` to install dependencies
- If any script fails with an error, check the error message and try running it again
- Make sure all directories (tools, evidence, reports, etc.) exist before running the scripts
- If a script hangs, you can press Ctrl+C to cancel it and try again
