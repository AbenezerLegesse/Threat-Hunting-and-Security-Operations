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
| where DeviceName == "windows-lab-tes"
```

**Analytical Significance:** Establishing baseline telemetry visibility is critical before drawing conclusions. This ensures the endpoint is actively reporting and that the absence of certain events is meaningful.

![Figure 1: Initial Telemetry Review](./images/telemetry_baseline.png)

---

### Phase 2: Detection of Abnormal Network Behavior
Once telemetry was confirmed, I shifted focus to identifying devices with unusual failed connection activity.

**2. Failed Connection Analysis**
To identify systems generating excessive connection failures, I used the following query:

```kusto
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize connectioncount = count() by DeviceName, ActionType, RemoteIP, LocalIP
| order by connectioncount desc
```

This analysis revealed several systems with high failed connection counts:

| Device | Failed Connections | Target IP |
|--------|-------------------|-----------|
| windows-target- | 156 | 10.0.0.198 |
| yves-windows11 | 138 | 10.0.0.155 |
| onboarding | 104 | 10.0.0.198 |
| abdiazizonboard | 78 | 10.0.0.198 |

Among these systems, `10.0.0.155` (windows-target-) stood out as the most suspicious source for deeper analysis.

![Figure 2: Failed Connection Summary](./images/failed_connections.png)

---

### Phase 3: Port Scan Confirmation
After identifying the suspicious source IP, I reviewed its failed connections in chronological order.

**3. Focused Review of Suspected Host**

```kusto
let IPInQuestion = "10.0.0.155";
DeviceNetworkEvents
| where LocalIP == IPInQuestion
| where ActionType == "ConnectionFailed"
| order by Timestamp desc
```

**Observation:** The results showed a rapid sequence of connection attempts from `10.0.0.155` to `10.0.0.159` across many different ports, including 21, 22, 23, 25, 53, 80, 110, 123, 137, 138, 143, 161, 194, 443, 465, 587, 993, 995, 3306, 5900, 8080, and 8443. This pattern is strongly indicative of port-scanning behavior, where a host systematically probes services on another system to identify open or accessible ports.

![Figure 3: Port Scan Activity](./images/port_scan.png)

---

### Phase 4: Process Correlation
After identifying suspicious network behavior, I pivoted to process telemetry to determine what caused the activity.

**4. Process Activity Around the Time of the Scan**

```kusto
let VMName = "windows-target-";
let specificTime = datetime(2026-04-10T04:40:58.3065254Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```

**Observation:** I observed `powershell.exe` launching around the time of the scan, with command-line evidence showing that it downloaded and saved a script named `portscan.ps1` to `C:\ProgramData\portscan.ps1`. This strongly supported that the scanning activity was initiated through PowerShell script execution.

![Figure 4: Process Timeline](./images/process_timeline.png)

---

### Phase 5: File Validation
To validate the process findings, I checked whether the referenced file actually existed on disk.

**5. Verification of Script on Host**
I navigated to the following path: `C:\ProgramData\portscan.ps1`

The file was present on disk, confirming that the PowerShell process successfully downloaded and created the script on the endpoint.

![Figure 5: File Presence Confirmation](./images/file_validation.png)

---

### Phase 6: Account Context Attribution
After confirming script execution, I investigated which account launched the activity.

**6. Identify the Account Responsible**

```kusto
let VMName = "windows-lab-tes";
let specificTime = datetime(2026-04-10T04:36:54.9290569Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| where InitiatingProcessCommandLine contains "portscan"
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine, AccountName
```

**Observation:** The results showed that the process was executed under the `SYSTEM` account. This is notable because SYSTEM is a high-privilege built-in account, and script-driven network scanning under this context is suspicious and not typical of normal user activity.

![Figure 6: Account Attribution](./images/account_attribution.png)

---

## 📊 Findings Summary

| Finding | Status | Detail |
| :--- | :--- | :--- |
| **Telemetry Availability** | ✅ Confirmed | The device was actively reporting to MDE. |
| **Suspicious Network Activity** | 🚨 Detected | Excessive failed internal connection attempts observed. |
| **Port Scanning Behavior** | 🚨 Confirmed | One host attempted many ports on another internal host. |
| **PowerShell Involvement** | ⚠️ Confirmed | `powershell.exe` downloaded and executed `portscan.ps1`. |
| **File Presence on Disk** | ✅ Confirmed | `portscan.ps1` existed in `C:\ProgramData`. |
| **Privileged Execution Context** | ⚠️ Confirmed | The activity executed under the `SYSTEM` account. |

### MITRE ATT&CK Mapping
* **T1046 – Network Service Discovery:** Port scanning internal hosts.
* **T1059.001 – Command and Scripting Interpreter: PowerShell:** Script execution for reconnaissance.
* **T1105 – Ingress Tool Transfer:** Downloaded `portscan.ps1` from external source.

---

## 🛠️ Response & Strategic Recommendations

Based on the confirmed suspicious activity, I initiated immediate containment and identified several hardening opportunities.

### Immediate Tactical Actions
* **Device Isolation:** Isolated the endpoint to stop further reconnaissance activity.
* **Malware Scan:** Initiated a malware scan on the host to check for additional malicious files, scripts, or persistence mechanisms related to the attack.
* **Evidence Validation:** Confirmed both process and file artifacts associated with the activity.
* **Documentation:** Recorded the network, process, and file evidence for reporting and follow-up.

### Long-Term Strategic Improvements
* **Restrict Internal Host-to-Host Traffic:** Apply segmentation and internal firewall controls rather than allowing unrestricted internal communication.
* **Control PowerShell Execution:** Implement stronger monitoring and restrictions such as script block logging, execution policy enforcement, and constrained language mode.
* **Use Application Control:** Prevent unauthorized scripts through AppLocker or WDAC.
* **Create Detection Rules for Internal Scanning:** Alert on high volumes of failed connections and rapid multi-port access patterns.
* **Review SYSTEM-Level Script Activity:** Treat script execution under SYSTEM as higher priority for investigation.

---

## 📝 Conclusion
This investigation confirmed that the observed internal network slowdown was associated with suspicious internal reconnaissance behavior. By correlating `DeviceNetworkEvents`, `DeviceProcessEvents`, and `DeviceFileEvents`, I verified that a PowerShell script named `portscan.ps1` was downloaded, written to disk, and executed under the `SYSTEM` account. The resulting activity matched known reconnaissance behavior and aligned with T1046, T1059.001, and T1105 in the MITRE ATT&CK framework.

The device was isolated and a malware scan was initiated to prevent further activity. The investigation also highlighted the need for better internal segmentation, stronger script controls, and improved detections for suspicious internal scanning behavior.

---

## 📂 Appendix: KQL Query Library

### 1) Initial telemetry review
```kusto
DeviceNetworkEvents
| order by Timestamp desc
| where DeviceName == "windows-lab-tes"

DeviceFileEvents
| order by Timestamp desc
| where DeviceName == "windows-lab-tes"

DeviceProcessEvents
| order by Timestamp desc
| where DeviceName == "windows-lab-tes"
```

### 2) Count failed connections
```kusto
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize connectioncount = count() by DeviceName, ActionType, RemoteIP, LocalIP
| order by connectioncount desc
```

### 3) Review failed connections for the suspected IP
```kusto
let IPInQuestion = "10.0.0.155";
DeviceNetworkEvents
| where LocalIP == IPInQuestion
| where ActionType == "ConnectionFailed"
| order by Timestamp desc
```

### 4) Review process events around the suspicious time
```kusto
let VMName = "windows-target-";
let specificTime = datetime(2026-04-10T04:40:58.3065254Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```

### 5) Identify the account that launched the script
```kusto
let VMName = "windows-lab-tes";
let specificTime = datetime(2026-04-10T04:36:54.9290569Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| where InitiatingProcessCommandLine contains "portscan"
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine, AccountName
```
