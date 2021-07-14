# capstone-engagement-ft
Assessment, analysis and hardening of a vulnerable machine with roles as both red and blue team

## Table of Contents
This document contains the following sections:
1. **Network Topology**
2. **Red Team**: Security Assessment
3. **Blue Team**: Log Analysis and Attack Characterization
4. **Hardening**: Proposed Alarms and Mitigation Strategies

## Network Topology
! [Network Topology](/Diagrams/NetworkTopology.png)

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

