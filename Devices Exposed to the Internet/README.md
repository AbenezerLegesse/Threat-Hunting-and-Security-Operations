# Threat Hunting Scenario: Internet-Exposed Windows Asset Investigation

## Executive Summary
**Status:** Investigation Concluded - No Evidence of Compromise
**Objective:** To identify and assess the risk of a Windows Virtual Machine (VM) inadvertently exposed to the public internet via Microsoft Defender for Endpoint (MDE) telemetry.

During this proactive threat hunt, I investigated the exposure of a specific Windows asset (`windows-target-`) and analyzed authentication patterns to detect potential brute-force or password-spraying campaigns. While the investigation confirmed significant opportunistic scanning and failed logon attempts from multiple external malicious IP addresses, a deep-dive analysis of successful logon events and account history revealed no evidence of unauthorized access or successful credential exploitation.

## 🛡️ Professional Skills Demonstrated
* **Threat Hunting & Detection:** Proactive identification of attack patterns (Brute Force, Password Spraying).
* **Advanced Kusto Query Language (KQL):** Complex telemetry analysis using `DeviceLogonEvents` and `DeviceInfo`.
* **Microsoft Defender for Endpoint (MDE):** Expert use of Advanced Hunting and Device Inventory for endpoint visibility.
* **Incident Investigation:** Systematic verification of telemetry, exposure validation, and forensic correlation.
* **Risk Mitigation:** Strategic recommendation of security controls based on observed threat actor behavior.

## 🚀 Project Overview
In modern enterprise environments, "shadow IT" or configuration drift can lead to sensitive assets being exposed to the public internet. This project demonstrates a professional investigation into such a scenario, simulating the response to a security finding where an internet-facing Windows host was detected.

### Scenario Objective
The goal was to validate the exposure of the target VM, quantify the scale of external authentication attempts, and perform a forensic correlation to ensure that failed attempts did not escalate into successful unauthorized access.

### Technical Stack
* **Platform:** Microsoft Defender for Endpoint (MDE)
* **Interface:** Microsoft Defender Advanced Hunting
* **Language:** Kusto Query Language (KQL)
* **Framework:** MITRE ATT&CK

---

## 🔍 Investigation Methodology

### Phase 1: Asset Validation & Telemetry Verification
The first step was to establish a baseline of visibility. I verified that the target asset was correctly onboarded and actively reporting telemetry to ensure the integrity of the investigation.

**1. Onboarding Verification**
I confirmed the presence of `windows-target-` within the MDE Device Inventory.

![Figure 1: MDE Device Inventory](https://github.com/user-attachments/assets/8aa00707-a828-4f4b-b2ad-6e6aa4921646)

**2. Telemetry Integrity Check**
Using the `DeviceInfo` table, I confirmed the device was actively transmitting endpoint data.

```kusto
DeviceInfo
| where DeviceName == "windows-target-"
```

**Analytical Significance:** Establishing telemetry continuity is critical to ensure that absence of evidence is not mistaken for evidence of absence.

![Figure 2: DeviceInfo Telemetry Confirmation](https://github.com/user-attachments/assets/f3a2bdbd-9939-4b85-a1ec-80f53b5ccf06)

---

### Phase 2: Exposure Assessment
Once telemetry was confirmed, I validated the specific exposure vector.

**3. Internet-Facing Validation**
I queried the `IsInternetFacing` attribute within the `DeviceInfo` table to confirm the asset's public exposure.

```kusto
DeviceInfo
| where DeviceName == "windows-target-"
| where IsInternetFacing == true
| order by Timestamp desc
```

The results confirmed the device was flagged as **internet-facing** with the public IP: `172.176.88.102`.

![Figure 3: Internet Exposure Confirmation](https://github.com/user-attachments/assets/7e106922-8151-475b-bb87-e466cb562e75)

---

### Phase 3: Threat Detection & Correlation

**4. Identifying Brute-Force Patterns**
With exposure confirmed, I analyzed `DeviceLogonEvents` to identify failed authentication attempts originating from external network interfaces.

```kusto
DeviceLogonEvents
| where DeviceName == "windows-target-"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts desc
```

**Observation:** The investigation identified high-frequency failed logon attempts from several external IPs, notably `94.26.68.54` (93 attempts) and `216.122.172.240` (64 attempts). This pattern is highly indicative of automated brute-force or password-spraying activity.

![Figure 4: Observed Brute-Force Activity](https://github.com/user-attachments/assets/46bf8a53-9edd-4d04-8f2c-77df70e8b5b4)

**5. Cross-Referencing Attacker Success**
To determine if the attack was successful, I correlated the identified malicious IP addresses against successful logon events.

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

**Result:** **Zero successful logons** were identified from these aggressive sources, significantly reducing the immediate risk of compromise via these specific vectors.

![Figure 5: Absence of Attacker Success](https://github.com/user-attachments/assets/311ff2e2-5134-475c-9f10-c1ba02116cad)

**6. Comprehensive Account Audit**
To ensure no other account was compromised, I performed a full review of all successful logons and checked for "failed-to-success" patterns on those accounts.

*   **Successful Logons Found:** 4 (all associated with expected system/local activity).
*   **Account Audit:** Accounts such as `dwm-1`, `umfd-1`, and `umfd-0` were audited for prior failed attempts. No suspicious patterns were found.

---

## 📊 Findings Summary

| Finding | Status | Detail |
| :--- | :--- | :--- |
| **Asset Onboarding** | ✅ Confirmed | Device is fully visible in MDE. |
| **Internet Exposure** | ⚠️ Verified | Asset is actively internet-facing via public IP. |
| **Hostile Activity** | 🚨 Detected | High-volume brute-force/password spraying observed. |
| **Unauthorized Access**| ✅ Not Detected | No successful logons from attacking IPs; no failed-to-success patterns. |

### MITRE ATT&CK Mapping
* **T1110 – Brute Force:** Observed via repeated failed authentication attempts.
* **T1110.003 – Password Spraying:** Inferred from distributed failed login activity across multiple IPs.

---

## 🛠️ Remediation & Strategic Recommendations

While no compromise was confirmed, the presence of active targeting necessitates immediate hardening to prevent future successful exploitations.

### Immediate Tactical Actions
* **Reduce Attack Surface:** Remove unnecessary public internet exposure for this VM.
* **Network Hardening:** Implement Network Security Group (NSG) rules to restrict RDP/management access to authorized IP ranges/VPN only.
* **Access Control:** Enforce Multi-Factor Authentication (MFA) for all interactive logins.

### Long-Term Strategic Improvements
* **Policy Enforcement:** Implement strict account lockout and "Smart Lockout" policies to mitigate brute-force efficacy.
* **Continuous Monitoring:** Automate alerts for `IsInternetFacing == true` combined with `LogonFailed` spikes in MDE.
* **Zero Trust Architecture:** Transition toward Bastion-based access for all administrative interfaces.

---

## 📝 Conclusion
The investigation confirmed that while the target asset was successfully targeted by opportunistic attackers, the existing security posture (or lack of attacker success) prevented a breach. The presence of brute-force activity underscores the critical need to remediate the identified internet exposure to maintain a robust security posture.

---
## 📂 Appendix: KQL Query Library

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
