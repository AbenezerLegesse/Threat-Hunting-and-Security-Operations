# Threat Hunting Scenario 1: Devices Exposed to the Internet

## Project Overview
This threat hunting project investigated whether an internet-exposed Windows virtual machine in Microsoft Defender for Endpoint (MDE) had been targeted by external attackers and whether any brute-force login attempts were successful.

The investigation focused on the VM **`windows-target-`**, which was confirmed to be onboarded to MDE, actively reporting telemetry, and marked as internet-facing. After validating exposure, I analyzed authentication logs in Microsoft Defender Advanced Hunting to identify failed remote logon attempts, investigate the most aggressive source IP addresses, and determine whether any attacker successfully authenticated to the host.

## Scenario Objective
During routine maintenance, the security team needed to identify systems in the environment that were mistakenly exposed to the public internet and determine whether those systems experienced brute-force login attempts or unauthorized access.

### Hunt Goal
- Identify whether the target VM was internet-facing
- Determine whether it received excessive failed logon attempts from external IPs
- Investigate whether any failed attempts were followed by successful access
- Assess whether there was evidence of compromise
- Recommend improvements to prevent similar exposure in the future

## Hypothesis
Because the device was exposed to the public internet, it was likely to attract opportunistic scanning, password spraying, or brute-force attempts from automated bots or malicious actors. Since some older systems may not enforce account lockout policies, it was possible that repeated failed login attempts could eventually result in unauthorized access.

## Environment
- **Platform:** Microsoft Defender for Endpoint (MDE)
- **Hunting Interface:** Advanced Hunting
- **Target Device:** `windows-target-`
- **Relevant Tables:**
  - `DeviceInfo`
  - `DeviceLogonEvents`

## Investigation Workflow
1. Verify the target VM is onboarded to Microsoft Defender for Endpoint
2. Confirm the VM is actively reporting telemetry
3. Validate that the device is internet-facing
4. Identify failed remote logon attempts from external IP addresses
5. Check whether the most aggressive IP addresses later succeeded
6. Review all successful logons on the VM
7. Investigate whether the accounts tied to successful logons had prior failed attempts
8. Conclude whether brute-force activity led to compromise

---

## Step 1: Verify the Target VM Is Onboarded to MDE
To begin the investigation, I first confirmed that the target VM was successfully onboarded to Microsoft Defender for Endpoint. In the **Device Inventory** page, I searched for the device name and verified that **`windows-target-`** appeared in the environment.

This confirmed that the system was visible in Defender and available for hunting.


### Why this matters
- Confirms the endpoint is onboarded
- Ensures the device is visible in MDE
- Verifies the host can be investigated through Advanced Hunting

### Figure 1
**Microsoft Defender Device Inventory showing the onboarded target VM (`windows-target-`)**

<img width="1041" height="770" alt="Screenshot 2026-04-09 at 7 10 15 PM" src="https://github.com/user-attachments/assets/8aa00707-a828-4f4b-b2ad-6e6aa4921646" />


---

## Step 2: Confirm the Target VM Is Actively Reporting Telemetry
After locating the VM in Device Inventory, I validated that it was actively sending telemetry into MDE by querying the `DeviceInfo` table in Advanced Hunting.

```kusto
DeviceInfo
| where DeviceName == "windows-target-"
```

The query returned multiple records for the device, confirming that it was actively reporting endpoint data to Defender.

### Why this matters
- Confirms the device is actively sending telemetry
- Verifies that required hunting data is available
- Establishes that the system can be investigated using Defender log sources

### Key observation
The results showed the device had a recorded **public IP address: `172.176.88.102`**, suggesting that it may have been exposed to the internet.

### Figure 2
**Advanced Hunting query against `DeviceInfo` confirming active telemetry for `windows-target-`**

---
<img width="874" height="777" alt="Screenshot 2026-04-09 at 7 18 13 PM" src="https://github.com/user-attachments/assets/f3a2bdbd-9939-4b85-a1ec-80f53b5ccf06" />

## Step 3: Confirm the VM Was Internet-Facing
To verify the core scenario, I queried `DeviceInfo` again to determine whether the host was marked as internet-facing.

```kusto
DeviceInfo
| where DeviceName == "windows-target-"
| where IsInternetFacing == true
| order by Timestamp desc
```

The query returned multiple records showing that **`windows-target-`** was flagged as **internet-facing**. The results also displayed the public IP address **`172.176.88.102`**.

### Why this matters
- Confirms the device matched the scope of the hunt
- Validates that the exposure was real, not assumed
- Establishes a basis for investigating inbound hostile activity

### Analyst assessment
An internet-facing Windows host is a common target for scanning, password spraying, and brute-force attempts from malicious infrastructure or automated bots.

### Figure 3
**Advanced Hunting results showing `windows-target-` marked as internet-facing with public IP `172.176.88.102`**

---
<img width="1087" height="348" alt="Screenshot 2026-04-09 at 7 22 10 PM" src="https://github.com/user-attachments/assets/7e106922-8151-475b-bb87-e466cb562e75" />

## Step 4: Identify Failed Remote Logon Attempts
After confirming the VM was exposed to the internet, I queried `DeviceLogonEvents` to look for failed remote authentication attempts.

```kusto
DeviceLogonEvents
| where DeviceName == "windows-target-"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts desc
```

The results showed repeated failed logon attempts from multiple public IP addresses.

### Top observed failed logon sources
- `94.26.68.54` — 93 failed attempts
- `216.122.172.240` — 64 failed attempts
- `79.127.147.207` — 61 failed attempts
- `94.26.68.55` — 54 failed attempts
- `78.140.242.82` — 38 failed attempts
- `27.102.138.102` — 34 failed attempts
- `79.127.147.210` — 32 failed attempts

### Why this matters
- Confirms the internet-exposed VM was actively targeted
- Shows repeated login failures from multiple external sources
- Strongly suggests opportunistic brute-force or password-spraying behavior

### Analyst assessment
The pattern of repeated failed logons from several public IP addresses is consistent with automated hostile login activity against an exposed Windows asset.

### Figure 4
**Failed remote logon attempts against `windows-target-` from multiple external IP addresses**

---
<img width="1129" height="698" alt="Screenshot 2026-04-09 at 7 23 16 PM" src="https://github.com/user-attachments/assets/46bf8a53-9edd-4d04-8f2c-77df70e8b5b4" />


## Step 5: Check Whether the Top Failed Logon IPs Later Succeeded
Next, I investigated whether the most aggressive source IP addresses later achieved successful authentication.

```kusto
let RemoteIPsInQuestion = dynamic([
    "94.26.68.54",
    "216.122.172.240",
    "79.127.147.207",
    "94.26.68.55",
    "78.140.242.82"
]);
DeviceLogonEvents
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

This query returned **no results** in the selected timeframe.

### Why this matters
- Shows the most persistent attacking IPs did **not** successfully authenticate
- Reduces the likelihood that the highest-volume brute-force activity led to compromise
- Helps narrow the investigation away from those specific external sources

### Analyst assessment
Although the target VM was receiving repeated login attempts from the internet, there was no evidence that the top five most aggressive IP addresses were able to successfully log in.

### Figure 5
**No successful logons found for the top external IP addresses responsible for the highest number of failed attempts**

---
<img width="1201" height="380" alt="Screenshot 2026-04-09 at 7 25 01 PM" src="https://github.com/user-attachments/assets/311ff2e2-5134-475c-9f10-c1ba02116cad" />


## Step 6: Review All Successful Logons on the Target VM
To better understand whether any successful access occurred on the system, I reviewed all successful logon events for the device.

```kusto
DeviceLogonEvents
| where DeviceName == "windows-target-"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
```

The query returned **4 successful logon events** within the last 30 days.

### Why this matters
- Establishes a baseline of successful authentication activity
- Shows successful logons were limited during the review period
- Supports the earlier finding that brute-force sources were not tied to successful access

### Initial assessment
The successful logons appeared to be associated with expected local or system-related accounts rather than the external IP addresses that generated the repeated failures.

### Figure 6
**Successful logon events observed on `windows-target-` during the review period**

<img width="1428" height="363" alt="Screenshot 2026-04-09 at 7 27 56 PM" src="https://github.com/user-attachments/assets/8980155d-2af6-49bd-9e34-dfd6dc0100ce" />


## Step 7: Check Whether Successful Accounts Had Prior Failed Attempts
To test for a classic brute-force pattern of **many failed attempts followed by a success**, I investigated whether the accounts tied to successful logons had any failed logon history.

The accounts reviewed were:
- `dwm-1`
- `umfd-1`
- `umfd-0`

Queries used:

```kusto
DeviceLogonEvents
| where DeviceName == "windows-target-"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where AccountName == "dwm-1"
| where ActionType == "LogonFailed"
```
<img width="1201" height="380" alt="Screenshot 2026-04-09 at 7 25 01 PM" src="https://github.com/user-attachments/assets/bea42367-5f97-4c29-b308-a1300e6cce0d" />

```kusto

```kusto
DeviceLogonEvents
| where DeviceName == "windows-target-"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where AccountName == "umfd-1"
| where ActionType == "LogonFailed"
```
<img width="1201" height="380" alt="Screenshot 2026-04-09 at 7 25 01 PM" src="https://github.com/user-attachments/assets/bea42367-5f97-4c29-b308-a1300e6cce0d" />

```kusto
DeviceLogonEvents
| where DeviceName == "windows-target-"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where AccountName == "umfd-0"
| where ActionType == "LogonFailed"
```


<img width="1201" height="380" alt="Screenshot 2026-04-09 at 7 25 01 PM" src="https://github.com/user-attachments/assets/b6f6987a-99bd-482c-b85e-13035b5df995" />

All three queries returned **zero failed logon events** for those accounts.

### Why this matters
- No failed-to-success pattern was observed for those accounts
- Reduces the likelihood that the successful logons were the result of brute-force activity
- Supports the conclusion that the successful logons were more likely benign system-related activity

### Analyst assessment
Because there were no failed logon attempts tied to `dwm-1`, `umfd-1`, or `umfd-0`, the successful events linked to those accounts do not fit a brute-force success pattern.

> A one-off password guess cannot be completely ruled out, but there is no evidence of repeated failed authentication attempts against these accounts that would support a brute-force compromise scenario.

---

## Findings Summary
### What was confirmed
- The device **`windows-target-`** was successfully onboarded to Microsoft Defender for Endpoint
- The device was actively reporting telemetry into Advanced Hunting
- The device was confirmed as **internet-facing**
- The host received repeated failed authentication attempts from multiple public IP addresses
- The most aggressive attacking IPs did **not** achieve a successful logon
- Only **4 successful logons** were observed in the review window
- Those successful logons were not associated with prior failed attempts on the same accounts

---

## MITRE ATT&CK Mapping
Based on the activity observed, the following MITRE ATT&CK techniques are relevant:

- **T1110 – Brute Force**  
  Repeated failed authentication attempts from multiple public IP addresses suggest brute-force or password-spraying behavior.

- **T1110.003 – Password Spraying**  
  The distributed failed login activity from several public IPs may also align with password spraying against exposed services.

- **T1078 – Valid Accounts** *(not confirmed)*  
  This technique was considered during the investigation, but there was no evidence that attackers successfully used valid credentials.

---

## Response Actions
Because no confirmed compromise was found, response activity would focus on reducing exposure and preventing future attacks rather than full incident containment.

### Recommended response actions
- Remove unnecessary public exposure from the VM
- Restrict RDP or management services to trusted IP ranges only
- Apply NSG / firewall rules to block unwanted inbound access
- Enforce strong password requirements
- Configure account lockout thresholds to reduce brute-force risk
- Enable MFA where applicable
- Continue monitoring `DeviceLogonEvents` and `DeviceInfo` for exposure and authentication anomalies

---

## Improvement Opportunities
### Security improvements
- Avoid leaving Windows systems directly exposed to the public internet unless absolutely necessary
- Enforce account lockout or smart lockout policies
- Limit management access through VPN, Bastion, or IP allowlists
- Regularly audit internet-facing assets in Defender
- Use hardened administrative credentials and disable weak/default passwords


---

## Conclusion
This threat hunting scenario successfully validated that **`windows-target-`** was internet-facing and receiving repeated failed logon attempts from external IP addresses. The observed activity was consistent with opportunistic brute-force or password-spraying attacks commonly directed at exposed Windows systems.

However, after reviewing the most aggressive attacking IPs and all successful logon activity on the host, there was **no evidence of confirmed unauthorized access**. The attack attempts were unsuccessful, and the successful logons observed were not supported by failed-to-success authentication patterns. Even though brute-force activity was present, the attackers were **not able to get into the VM** based on the evidence available in this investigation.

---

## Appendix: Queries Used

### 1) Confirm device telemetry
```kusto
DeviceInfo
| where DeviceName == "windows-target-"
```

### 2) Confirm internet exposure
```kusto
DeviceInfo
| where DeviceName == "windows-target-"
| where IsInternetFacing == true
| order by Timestamp desc
```

### 3) Identify failed logons
```kusto
DeviceLogonEvents
| where DeviceName == "windows-target-"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts desc
```

### 4) Check whether top attacking IPs succeeded
```kusto
let RemoteIPsInQuestion = dynamic([
    "94.26.68.54",
    "216.122.172.240",
    "79.127.147.207",
    "94.26.68.55",
    "78.140.242.82"
]);
DeviceLogonEvents
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

### 5) Review all successful logons
```kusto
DeviceLogonEvents
| where DeviceName == "windows-target-"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
```

### 6) Check failed attempts for successful accounts
```kusto
DeviceLogonEvents
| where DeviceName == "windows-target-"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where AccountName == "dwm-1"
| where ActionType == "LogonFailed"
```

```kusto
DeviceLogonEvents
| where DeviceName == "windows-target-"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where AccountName == "umfd-1"
| where ActionType == "LogonFailed"
```

```kusto
DeviceLogonEvents
| where DeviceName == "windows-target-"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where AccountName == "umfd-0"
| where ActionType == "LogonFailed"
```
