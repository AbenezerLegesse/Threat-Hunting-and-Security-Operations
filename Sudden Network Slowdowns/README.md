# Threat-Hunting-and-Security-Operations
# Threat Hunting Scenario: Internal Port Scanning Investigation

## Executive Summary
**Status:** Investigation Concluded - Suspicious Internal Reconnaissance Confirmed  
**Objective:** To identify the cause of internal network slowdowns and determine whether a Windows Virtual Machine (VM) was conducting suspicious internal scanning activity using Microsoft Defender for Endpoint (MDE) telemetry.

During this proactive threat hunt, I investigated unusual network performance degradation affecting hosts in the `10.0.0.0/16` network. After reviewing network, process, and file telemetry in Microsoft Defender for Endpoint, I identified a Windows asset performing repeated failed connection attempts across multiple service ports on another internal host. Correlated evidence showed that the activity was driven by `powershell.exe`, which downloaded and executed a script named `portscan.ps1` from an external source. Additional analysis confirmed the file existed on disk and that the activity was executed under the `SYSTEM` account. Based on the evidence, the activity aligned with internal reconnaissance and port-scanning behavior.

## 🛡️ Professional Skills Demonstrated
* **Threat Hunting & Detection:** Proactive identification of abnormal internal scanning behavior.
* **Advanced Kusto Query Language (KQL):** Correlation of `DeviceNetworkEvents`, `DeviceProcessEvents`, and `DeviceFileEvents`.
* **Microsoft Defender for Endpoint (MDE):** Deep use of Advanced Hunting for endpoint investigation.
* **Incident Investigation:** Validation of suspicious process execution, file creation, and account context.
* **Threat Analysis:** Mapping suspicious behavior to MITRE ATT&CK techniques.
* **Response & Containment:** Isolation of the host and initiation of malware scanning.

## 🚀 Project Overview
In enterprise environments, internal traffic is often trusted more than it should be. If unrestricted host-to-host communication and unrestricted scripting are allowed, compromised or misused systems can perform reconnaissance against other internal assets without being blocked.

This project demonstrates a professional threat hunt into suspicious internal activity that was contributing to network performance issues. The investigation focused on determining whether a Windows host was generating excessive internal traffic due to file transfer activity, scanning behavior, or other malicious actions.

### Scenario Objective
The goal was to identify the source of the network slowdown, validate whether the behavior was malicious or suspicious, correlate process and file telemetry with network events, and document the findings in a defensible way.

### Technical Stack
* **Platform:** Microsoft Defender for Endpoint (MDE)
* **Interface:** Microsoft Defender Advanced Hunting
* **Language:** Kusto Query Language (KQL)
* **Framework:** MITRE ATT&CK
* **Operating System:** Windows VM

---

## 🔍 Investigation Methodology

### Phase 1: Telemetry Validation & Baseline Review
The first step was to confirm that the device was actively reporting telemetry and that the necessary event tables contained recent activity for investigation.

**1. Initial Log Review**
I began by reviewing the recent telemetry from the target device across the core hunting tables.

```kusto
DeviceNetworkEvents
| order by Timestamp desc 
| where DeviceName == "windows-lab-tes"

DeviceFileEvents
| order by Timestamp desc 
| where DeviceName == "windows-lab-tes"

DeviceProcessEvents
| order by Timestamp desc 
| where DeviceName =="windows-lab-tes"

Analytical Significance: Establishing baseline telemetry visibility is critical before drawing conclusions. This ensures the endpoint is actively reporting and that the absence of certain events is meaningful.
Phase 2: Detection of Abnormal Network Behavior
Once telemetry was confirmed, I shifted focus to identifying devices with unusual failed connection activity.
2. Failed Connection Analysis
To identify systems generating excessive connection failures, I used the following query:

DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize connectioncount = count() by DeviceName, ActionType, RemoteIP, LocalIP
| order by connectioncount

This analysis revealed several systems with high failed connection counts, including:
windows-target-: 156 failed connections
10.0.0.155 attempted to connect to 10.0.0.198
yves-windows11: 138 failed connections
10.0.0.112 attempted to connect to 10.0.0.155
onboarding: 104 failed connections
10.0.0.111 attempted to connect to 10.0.0.198
abdiazizonboard: 78 failed connections
10.0.0.10 attempted to connect to 10.0.0.198
Among these systems, 10.0.0.155 stood out as the most suspicious source for deeper analysis.

Phase 3: Port Scan Confirmation
After identifying the suspicious source IP, I reviewed its failed connections in chronological order.
3. Focused Review of Suspected Host

let IPInQuestion = "10.0.0.155";
DeviceNetworkEvents
| where LocalIP == IPInQuestion
| where ActionType == "ConnectionFailed"
| order by Timestamp desc

Observation: The results showed a rapid sequence of connection attempts from 10.0.0.155 to 10.0.0.159 across many different ports, including 21, 22, 23, 25, 53, 80, 110, 123, 137, 138, 143, 161, 194, 443, 465, 587, 993, 995, 3306, 5900, 8080, and 8443.
This pattern is strongly indicative of port-scanning behavior, where a host systematically probes services on another system to identify open or accessible ports.

Phase 4: Process Correlation
After identifying suspicious network behavior, I pivoted to process telemetry to determine what caused the activity.
4. Process Activity Around the Time of the Scan

let VMName = "windows-target-";
let specificTime = datetime(2026-04-10T04:40:58.3065254Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine

Observation: I observed powershell.exe launching around the time of the scan, with command-line evidence showing that it downloaded and saved a script named portscan.ps1 to:
C:\ProgramData\portscan.ps1
This strongly supported that the scanning activity was initiated through PowerShell script execution.


Phase 5: File Validation
To validate the process findings, I checked whether the referenced file actually existed on disk.
5. Verification of Script on Host
I navigated to the following path:
C:\ProgramData\portscan.ps1
The file was present on disk, confirming that the PowerShell process successfully downloaded and created the script on the endpoint.


Phase 6: Account Context Attribution
After confirming script execution, I investigated which account launched the activity.
6. Identify the Account Responsible

let VMName = "windows-lab-tes";
let specificTime = datetime(2026-04-10T04:36:54.9290569Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| where InitiatingProcessCommandLine contains "portscan"
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine, AccountName

Observation: The results showed that the process was executed under the SYSTEM account.
This is notable because SYSTEM is a high-privilege built-in account, and script-driven network scanning under this context is suspicious and not typical of normal user activity.


| Finding                          | Status       | Detail                                                   |
| :------------------------------- | :----------- | :------------------------------------------------------- |
| **Telemetry Availability**       | ✅ Confirmed  | The device was actively reporting to MDE.                |
| **Suspicious Network Activity**  | 🚨 Detected  | Excessive failed internal connection attempts observed.  |
| **Port Scanning Behavior**       | 🚨 Confirmed | One host attempted many ports on another internal host.  |
| **PowerShell Involvement**       | ⚠️ Confirmed | `powershell.exe` downloaded and executed `portscan.ps1`. |
| **File Presence on Disk**        | ✅ Confirmed  | `portscan.ps1` existed in `C:\ProgramData`.              |
| **Privileged Execution Context** | ⚠️ Confirmed | The activity executed under the `SYSTEM` account.        |

I used this command to identify who launch the attack 
// Observe DeviceProcessEvents for the past 10 minutes of the unusual activity found
let VMName = "windows-lab-tes";
let specificTime = datetime(2026-04-10T04:36:54.9290569Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| where InitiatingProcessCommandLine contains "portscan"
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine, AccountName

I used the query to identify which account launched the attack. The results showed that the activity was executed under the SYSTEM account, which is unusual because it indicates the port scan was not run by a normal user account. Based on this suspicious activity, I isolated the device to prevent any further malicious actions. I also initiated a malware scan on the host to check for additional malicious files, scripts, or persistence mechanisms related to the attack.


🛠️ Response & Strategic Recommendations
Based on the confirmed suspicious activity, I initiated immediate containment and identified several hardening opportunities.
Immediate Tactical Actions
Device Isolation: Isolated the endpoint to stop further reconnaissance activity.
Malware Scan: Initiated a malware scan on the host.
Evidence Validation: Confirmed both process and file artifacts associated with the activity.
Documentation: Recorded the network, process, and file evidence for reporting and follow-up.
Long-Term Strategic Improvements
Restrict Internal Host-to-Host Traffic: Apply segmentation and internal firewall controls rather than allowing unrestricted internal communication.
Control PowerShell Execution: Implement stronger monitoring and restrictions such as script block logging, execution policy enforcement, and constrained language mode.
Use Application Control: Prevent unauthorized scripts through AppLocker or WDAC.
Create Detection Rules for Internal Scanning: Alert on high volumes of failed connections and rapid multi-port access patterns.
Review SYSTEM-Level Script Activity: Treat script execution under SYSTEM as higher priority for investigation


📝 Conclusion
This investigation confirmed that the observed internal network slowdown was associated with suspicious internal reconnaissance behavior. By correlating DeviceNetworkEvents, DeviceProcessEvents, and DeviceFileEvents, I verified that a PowerShell script named portscan.ps1 was downloaded, written to disk, and executed under the SYSTEM account. The resulting activity matched known reconnaissance behavior and aligned with T1046, T1059.001, and T1105 in the MITRE ATT&CK framework.
The device was isolated and a malware scan was initiated to prevent further activity. The investigation also highlighted the need for better internal segmentation, stronger script controls, and improved detections for suspicious internal scanning behavior.


📂 Appendix: KQL Query Library
1) Initial telemetry review
DeviceNetworkEvents
| order by Timestamp desc 
| where DeviceName == "windows-lab-tes"
DeviceFileEvents
| order by Timestamp desc 
| where DeviceName == "windows-lab-tes"
DeviceProcessEvents
| order by Timestamp desc 
| where DeviceName =="windows-lab-tes"
2) Count failed connections
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize connectioncount = count() by DeviceName, ActionType, RemoteIP, LocalIP
| order by connectioncount
3) Review failed connections for the suspected IP
let IPInQuestion = "10.0.0.155";
DeviceNetworkEvents
| where LocalIP == IPInQuestion
| where ActionType == "ConnectionFailed"
| order by Timestamp desc
4) Review process events around the suspicious time
let VMName = "windows-target-";
let specificTime = datetime(2026-04-10T04:40:58.3065254Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
5) Identify the account that launched the script
let VMName = "windows-lab-tes";
let specificTime = datetime(2026-04-10T04:36:54.9290569Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| where InitiatingProcessCommandLine contains "portscan"
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine, AccountName

If you want, I can also make this even more polished with your exact image labels like `Figure 1`, `Figure 2`, and cleaner GitHub-ready spacing.







Image 1


DeviceNetworkEvents
| order by Timestamp desc 
| where DeviceName == "windows-lab-tes"

DeviceFileEvents
| order by Timestamp desc 
| where DeviceName == "windows-lab-tes"

DeviceProcessEvents
| order by Timestamp desc 
| where DeviceName =="windows-lab-tes"

Image 2


DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize connectioncount = count() by DeviceName, ActionType, RemoteIP, LocalIP
| order by connectioncount

Image 3



•  windows-target-  : had 156 failed connections 
•	10.0.0.155 tried to connect to 10.0.0.198
•  yves-windows11  : had 138 failed connections 
•	10.0.0.112 tried to connect to 10.0.0.155
•  onboarding : had 104 failed connections 
•	10.0.0.111 tried to connect to 10.0.0.198
•  abdiazizonboard  : had 78 failed connections 
•	10.0.0.10 tried to connect to 10.0.0.198


// Observe all failed connections for the IP in question. Notice anything?
let IPInQuestion = "10.0.0.155";
DeviceNetworkEvents
| where LocalIP == IPInQuestion
| where ActionType == "ConnectionFailed"
| order by Timestamp desc
 Image 4 and 5
After reviewing the failed connection attempts from the suspected host 10.0.0.155 in chronological order, I observed a port scan against 10.0.0.159. This is indicated by the rapid sequence of connection attempts to multiple different destination ports, including 21, 22, 23, 25, 53, 80, 110, 123, 137, 138, 143, 161, 194, 443, 465, 587, 993, 995, 3306, 5900, 8080, and 8443. The activity was initiated by powershell.exe running C:\programdata\portscan.ps1, which strongly supports that the host was performing scripted port-scanning activity.

// Observe DeviceProcessEvents for the past 10 minutes of the unusual activity found
let VMName = "windows-target-";
let specificTime = datetime(2026-04-10T04:40:58.3065254Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine


I pivoted to the DeviceProcessEvents table to look for suspicious activity around the time of the port scan. I observed powershell.exe launching at 2026-04-10T04:36:48.1660823Z, and the command line showed it downloading and saving a script named portscan.ps1 to C:\ProgramData\portscan.ps1. indicating the scan was likely run through script.
Image 6 and 7 or 8 / 11, 12,13

I then navigated to C:\ProgramData\portscan.ps1 to verify whether the portscan script actually existed on the host. I confirmed that the file was present in the C:\ProgramData directory, which supports the earlier evidence from DeviceProcessEventsshowing PowerShell downloaded and created portscan.ps1 on the system.
Image 9 and 10  
I used this command to identify who launch the attack 
// Observe DeviceProcessEvents for the past 10 minutes of the unusual activity found
let VMName = "windows-lab-tes";
let specificTime = datetime(2026-04-10T04:36:54.9290569Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| where InitiatingProcessCommandLine contains "portscan"
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine, AccountName

I used the query to identify which account launched the attack. The results showed that the activity was executed under the SYSTEM account, which is unusual because it indicates the port scan was not run by a normal user account. Based on this suspicious activity, I isolated the device to prevent any further malicious actions. I also initiated a malware scan on the host to check for additional malicious files, scripts, or persistence mechanisms related to the attack.
Image 14 and 15



