# capstone-engagement-ft
Assessment, analysis and hardening of a vulnerable machine with roles as both red and blue team

## Table of Contents
This document contains the following sections:
1. **Network Topology**
2. **Red Team**: Security Assessment
3. **Blue Team**: Log Analysis and Attack Characterization
4. **Hardening**: Proposed Alarms and Mitigation Strategies

## Network Topology
![Network Topology](https://github.com/francescatirpak/capstone-engagement-ft/blob/main/Diagrams/NetworkTopology.png)

## Red Team: Security Assessment

### Recond: Describing the Target
Nmap identified the following hosts on the network:

| Hostname         | IP address     | Role on Network            |
|------------------|----------------|----------------------------|
| Capstone         | 192.168.1.105  | Web Server                 | 
| ELK              | 192.168.1.100  | SIEM System                |
| ML-RefVm-684427  | 192.168.1.1    | NATswitch                  |
| Kali             | 192.168.1.90   | Penetration Testing System |

### Vulnerability Assessment
The assessment uncovered the following critical vulnerabilities in the target:

**Vulnerability**
Apache Web Server allows directory listing to be viewed by public user.
**Description**
Attacker is able to utilize browser to read entire contents of directories on Capstone Apache web server.
**Impact**
Investigation of publicly readable files reveals user “Ashton” is administrator for directory: “/company_folders/secret_folder/”

**Vulnerability**
Weak login security.
**Description**
Weak password revealed under “rockyou” wordlist. No lockout for any amount of failed login attempts.
**Impact**
Brute force attack successful providing access to “/secret_folder/”
Password hash revealed for user “Ryan” and secure access instructions for connection to WebDAV server.

**Vulnerability**
Persistent reverse shell backdoor.
**Description**
Weak security on WebDAV server allows deployment of reverse shell payload exploit on web server. IPS/IDS/Firewall rules have open ports and allow undetected reverse shell.
**Impact**
Remote backdoor shell access gained to Capstone Apache web server. Flag discovered, and many files readable from session.

### Exploitation: Apache Web Server Directories

**01. Tools & Processes**
Navigating to 192.168.1.105 with any web browser & investigating any folders.

![Apache Web Server Tools & Processes](https://github.com/francescatirpak/capstone-engagement-ft/blob/main/Images/ApacheWebServer_ToolsProcesses.png)

 **02. Achievements**
Most pages on Apache Web Server directories direct questions to page “/company_folders/secret_folder/” which is locked behind authentication page.

Reviewed files for further reconnaissance and discovered user Ashton is admin for secret folder.

**03. Screenshots**
![Apache Web Server Directories Exploitation](https://github.com/francescatirpak/capstone-engagement-ft/blob/main/Images/ApacheWebServer_Achievements.png)

