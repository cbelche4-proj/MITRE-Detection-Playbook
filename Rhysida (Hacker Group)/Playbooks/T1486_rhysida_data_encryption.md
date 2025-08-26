# Playbook: Rhysida Ransomware – Data Encrypted for Impact (T1486)

## 1. Purpose
Detect and respond to **file encryption events** consistent with Rhysida ransomware operations.  
Goal: identify ransomware encryption early, contain compromised systems, and guide triage and recovery efforts.

---

## 2. Scope & Preconditions
- **Environment:** Windows endpoints, file servers, and domain controllers.  
- **Data Sources Required:**
  - Windows Security Logs (4663 – file access, 4688 – process creation)
  - Sysmon (Event ID 11 – file create, Event ID 1 – process creation)
  - EDR/AV telemetry (Defender for Endpoint, CrowdStrike, etc.)
  - File server auditing (FSRM, NetApp/EMC logging)
  - SMB/network telemetry (sudden traffic spikes)  
- **Assumptions:** EDR/SIEM coverage present on all critical systems.

---

## 3. Hypothesis
> If Rhysida begins encrypting data, we will see **large-scale file modifications** with new extensions (`.rhysida`), suspicious parent processes, and mass file creation activity in a short timeframe.

---

## 4. MITRE Mappings
- **Primary Technique:** T1486 – Data Encrypted for Impact  
- **Related Techniques:**  
  - T1489 – Service Stop (disabling AV/backup services)  
  - T1490 – Inhibit System Recovery (deleting shadow copies)  
  - T1078 – Valid Accounts (for initial access)  
- **Frameworks:**  
  - NIST CSF: PR.DS-5, DE.CM-7, RS.MI-1  
  - CIS Controls: 10.6, 11.1, 11.4  

---

## 5. Detection Rules

### Sigma Rule
`/detections/sigma/rhysida_t1486.yml`
```yaml
title: Possible Rhysida Ransomware File Encryption
id: rhysida-t1486-encryption
status: experimental
description: Detects high-volume file writes consistent with ransomware encryption.
author: SOC Team
tags:
  - attack.t1486
logsource:
  category: file_access
  product: windows
detection:
  selection:
    EventID: 4663
    AccessMask: '0x2'
    ObjectType: 'File'
    ObjectName|endswith:
      - '.rhysida'
      - '.encrypted'
  timeframe: 1m
  condition: selection | count(ObjectName) by SubjectUserName > 50
fields:
  - SubjectUserName
  - ObjectName
  - ProcessName
falsepositives:
  - Bulk file renames/migrations
level: high
