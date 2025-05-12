# Windows Memory Forensics Lab

A hands-on lab for learning Windows memory forensics with a realistic Dark Kittens attack scenario.

## Lab Environment Diagram

![Lab Environment Diagram](https://github.com/sweetybsayani/Windows-Memory-Forensics-Lab/raw/main/lab_diagram.png)

## Introduction

This Windows Memory Forensics Lab provides a simulated environment for security professionals and students to practice memory forensics techniques against a realistic attack scenario. The lab features the Dark Kittens threat group, a fictional APT targeting Globomantics' critical infrastructure.

Through a series of guided exercises, you'll learn to:
- Analyze memory dumps using forensic techniques
- Identify malicious processes and network connections
- Extract indicators of compromise
- Investigate persistence mechanisms
- Document findings in a professional forensic report

## Lab Scenario

Globomantics security team has detected unusual activity on one of their critical workstations. The system appears to be communicating with suspicious external IPs, but traditional antivirus tools haven't detected any malware. You've been called in to analyze a memory dump from the compromised machine to identify potential Dark Kittens malware, establish persistence mechanisms, and determine what data may have been exfiltrated.

## Prerequisites

- Windows or Linux or MacOS 
- Command Prompt (CMD) or Terminal with Administrator privileges
- At least 8GB RAM
- 5 GB free disk space
- Internet connection for initial setup only
- Git installed (for cloning the repository)

## Detailed Setup Instructions

1. **Clone the Repository**:
   ```cmd
   git clone https://github.com/sweetybsayani/Windows-Memory-Forensics-Lab.git
   cd Windows-Memory-Forensics-Lab
   ```

2. **Run the Setup Script**:
   ```cmd
   python setup.py
   ```
   This script will:
   - Download and install Python (if not already installed)
   - Install required Python packages (pefile, yara-python, colorama, prettytable, tqdm, requests)
   - Download Volatility framework
   - Download sample memory dumps
   - Create working directories (tools, memory_dumps, evidence, reports, workdir)
   - Generate simulated artifacts for the lab

3. **Verify Installation**:
   After the setup completes, you should see the following message:
   ```
   LAB SETUP COMPLETE
   ======================================================================
   
   Your Windows Memory Forensics Lab is now set up and ready to use.
   
   To start the lab:
   1. Open Command Prompt
   2. Navigate to the lab directory
   3. Run: python analyze_memory.py
   
   Please follow the instructions in the README.md file for detailed steps.
   ======================================================================
   ```

## Lab Workflow

### Task 1: Analyze the Memory Dump
```cmd
python analyze_memory.py
```
- Choose option 1 (globomantics_workstation1.raw)
- Review the initial analysis results

### Task 2: Process Identification & Analysis
```cmd
python process_scanner.py globomantics_workstation1.raw
```
- Identify suspicious processes (PIDs 3244, 3536, 3724)
- Note the unusual process relationships and network connections

### Task 3: Evidence Collection & Analysis
```cmd
python evidence_collector.py globomantics_workstation1.raw 3244
python evidence_collector.py globomantics_workstation1.raw 3536
python evidence_collector.py globomantics_workstation1.raw 3724
```
- Analyze command lines, network connections, and memory strings
- Look for malicious behaviors in each process

### Task 4: Malware Indicators Extraction
```cmd
python ioc_extractor.py globomantics_workstation1.raw 3244 3536 3724
```
- Review the extracted Indicators of Compromise (IOCs)
- Study the MITRE ATT&CK techniques identified

### Task 5: Generate Forensic Report
```cmd
python report_generator.py
```
- Enter a report title, your name, and the suspicious PIDs
- Review the comprehensive HTML report in your browser
- Answer the reflection questions

## Key Learning Outcomes

By completing this lab, you will learn:

1. **Memory Forensics Fundamentals**:
   - How to analyze Windows memory dumps
   - Process analysis techniques
   - Memory artifact identification

2. **Malware Analysis**:
   - Identifying suspicious processes
   - Analyzing command line parameters
   - Decoding obfuscated commands

3. **Incident Response Skills**:
   - Extracting indicators of compromise
   - Documenting forensic findings
   - Mapping attack techniques to MITRE ATT&CK framework

4. **Persistence Mechanism Analysis**:
   - Registry-based persistence
   - Boot/startup persistence techniques
   - Detection methods

5. **Network Forensics**:
   - Identifying suspicious connections
   - C2 channel detection
   - Data exfiltration analysis

## Troubleshooting

- **Python Not Found**: Ensure Python is installed and in your PATH
- **Module Import Errors**: Run `pip install -r requirements.txt` to install dependencies
- **Permission Errors**: Make sure you're running CMD as Administrator
- **Script Errors**: Check error messages and ensure all directories exist


