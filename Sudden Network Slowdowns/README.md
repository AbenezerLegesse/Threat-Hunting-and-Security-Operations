# Threat Hunting Scenario: Internal Port Scanning Investigation

**Status:** Investigation Concluded - Suspicious Internal Reconnaissance Confirmed
**Date:** April 2026

## Executive Summary

This investigation identified the cause of internal network slowdowns affecting hosts in the `10.0.0.0/16` network range. Through analysis of Microsoft Defender for Endpoint (MDE) telemetry, I confirmed a Windows VM was conducting unauthorized internal port scanning activity.

Correlated evidence from `DeviceNetworkEvents`, `DeviceProcessEvents`, and `DeviceFileEvents` revealed that `powershell.exe` downloaded and executed a script (`portscan.ps1`) under the `SYSTEM` account, generating excessive failed connection attempts across multiple service ports on internal hosts.

## Professional Skills Demonstrated

| Skill Area | Specific Capability |
|------------|---------------------|
| **Threat Hunting** | Proactive identification of abnormal internal scanning behavior |
| **KQL Querying** | Advanced correlation across MDE event tables |
| **Microsoft Defender for Endpoint** | Deep investigation using Advanced Hunting |
| **Incident Response** | Host isolation and malware scan initiation |
| **MITRE ATT&CK Mapping** | Technique identification and documentation |

## Technical Environment

- **Platform:** Microsoft Defender for Endpoint (MDE)
- **Query Language:** Kusto Query Language (KQL)
- **Target System:** Windows VM (`windows-lab-test`)
- **Framework:** MITRE ATT&CK v14

---

## Investigation Methodology

### Phase 1: Telemetry Validation

Confirmed device was actively reporting telemetry across core event tables before drawing conclusions.

```kusto
DeviceNetworkEvents
| order by Timestamp desc
| where DeviceName == "windows-lab-test"

DeviceFileEvents
| order by Timestamp desc
| where DeviceName == "windows-lab-test"

DeviceProcessEvents
| order by Timestamp desc
| where DeviceName == "windows-lab-test"
```

**Significance:** Establishing baseline telemetry visibility ensures absence of certain events is meaningful.

### Phase 2: Detection of Abnormal Network Behavior

Identified systems generating excessive connection failures to pinpoint suspicious activity.

```kusto
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize connectioncount = count() by DeviceName, ActionType, RemoteIP, LocalIP
| order by connectioncount desc
```

**Key Findings:**

| Device | Failed Connections | Target IP |
|--------|-------------------|-----------|
| windows-target- | 156 | 10.0.0.198 |
| yves-windows11 | 138 | 10.0.0.155 |
| onboarding | 104 | 10.0.0.198 |
| abdiazizonboard | 78 | 10.0.0.198 |

Host `10.0.0.155` (windows-target-) emerged as the primary suspect with 156 failed connections.

### Phase 3: Port Scan Confirmation

Focused analysis on the suspected host revealed systematic port probing across multiple services.

```kusto
let IPInQuestion = "10.0.0.155";
DeviceNetworkEvents
| where LocalIP == IPInQuestion
| where ActionType == "ConnectionFailed"
| order by Timestamp desc
```

**Observation:** Rapid sequence of connection attempts from `10.0.0.155` to `10.0.0.159` across ports 21, 22, 23, 25, 53, 80, 110, 137-138, 143, 161, 443, 3306, 5900, 8080, and 8443. This pattern is indicative of port-scanning behavior.

### Phase 4: Process Correlation

Pivoted to process telemetry to identify the originating process.

```kusto
let VMName = "windows-target-";
let specificTime = datetime(2026-04-10T04:40:58.3065254Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```

**Finding:** `powershell.exe` downloaded and saved `portscan.ps1` to `C:\ProgramData\portscan.ps1` at `2026-04-10T04:36:48.1660823Z`.

### Phase 5: File Validation

Confirmed the script existed on disk at `C:\ProgramData\portscan.ps1`, validating PowerShell telemetry showed successful file creation.

### Phase 6: Account Attribution

Identified the account context for the scanning activity.

```kusto
let VMName = "windows-lab-test";
let specificTime = datetime(2026-04-10T04:36:54.9290569Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| where InitiatingProcessCommandLine contains "portscan"
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine, AccountName
```

**Critical Finding:** Activity executed under the `SYSTEM` account—a high-privilege context unusual for user-initiated scanning.

---

## Findings Summary

| Finding | Status | Details |
|---------|--------|---------|
| Telemetry Availability | ✅ Confirmed | Device actively reporting to MDE |
| Suspicious Network Activity | 🚨 Detected | Excessive failed internal connections |
| Port Scanning Behavior | 🚨 Confirmed | Systematic multi-port probing observed |
| PowerShell Involvement | ⚠️ Confirmed | Script downloaded and executed |
| File Presence on Disk | ✅ Confirmed | `portscan.ps1` in `C:\ProgramData` |
| Privileged Execution Context | ⚠️ Confirmed | Activity under `SYSTEM` account |

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Application |
|--------------|----------------|-------------|
| T1046 | Network Service Discovery | Port scanning internal hosts |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Script execution |
| T1105 | Ingress Tool Transfer | Downloaded `portscan.ps1` |

---

## Response Actions Taken

### Immediate Containment
- **Host Isolation:** Network-isolated `windows-target-` to prevent further reconnaissance
- **Malware Scan:** Initiated comprehensive endpoint scan for additional threats
- **Evidence Preservation:** Documented all network, process, and file artifacts

### Strategic Recommendations

1. **Network Segmentation:** Apply internal firewall controls rather than unrestricted host-to-host communication
2. **PowerShell Hardening:** Implement script block logging, execution policy enforcement, and constrained language mode
3. **Application Control:** Deploy AppLocker or WDAC to prevent unauthorized script execution
4. **Detection Rules:** Alert on high volumes of failed connections and rapid multi-port access patterns
5. **SYSTEM Account Monitoring:** Prioritize investigation of script execution under SYSTEM context

---

## Conclusion

This investigation confirmed that internal network slowdowns resulted from unauthorized reconnaissance activity. A Windows host (`10.0.0.155`) was systematically scanning internal targets using a PowerShell script downloaded from an external source and executed under the SYSTEM account.

The host has been isolated, malware scanning initiated, and findings documented for follow-up. This incident highlights the need for improved internal segmentation, stronger script controls, and enhanced detection for suspicious internal scanning behavior.

---

## Appendix: KQL Query Reference

### 1. Telemetry Baseline Review
```kusto
DeviceNetworkEvents | where DeviceName == "windows-lab-test" | order by Timestamp desc
DeviceFileEvents | where DeviceName == "windows-lab-test" | order by Timestamp desc
DeviceProcessEvents | where DeviceName == "windows-lab-test" | order by Timestamp desc
```

### 2. Failed Connection Aggregation
```kusto
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize connectioncount = count() by DeviceName, ActionType, RemoteIP, LocalIP
| order by connectioncount desc
```

### 3. Suspect IP Analysis
```kusto
let IPInQuestion = "10.0.0.155";
DeviceNetworkEvents
| where LocalIP == IPInQuestion
| where ActionType == "ConnectionFailed"
| order by Timestamp desc
```

### 4. Process Timeline Analysis
```kusto
let VMName = "windows-target-";
let specificTime = datetime(2026-04-10T04:40:58.3065254Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| project Timestamp, FileName, InitiatingProcessCommandLine
```

### 5. Account Attribution
```kusto
let VMName = "windows-lab-test";
let specificTime = datetime(2026-04-10T04:36:54.9290569Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| where InitiatingProcessCommandLine contains "portscan"
| project Timestamp, FileName, AccountName, InitiatingProcessCommandLine
```
