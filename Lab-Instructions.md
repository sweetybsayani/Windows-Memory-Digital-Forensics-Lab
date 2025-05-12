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


## Troubleshooting

- **Python Not Found**: Ensure Python is installed and in your PATH
- **Module Import Errors**: Run `pip install -r requirements.txt` to install dependencies
- **Permission Errors**: Make sure you're running CMD as Administrator
- **Script Errors**: Check error messages and ensure all directories exist


