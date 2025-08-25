# Playbook: Rhysida Ransomware – Data Encrypted for Impact (T1486)

## 1. Purpose
Detect and respond to **file encryption activity** consistent with Rhysida ransomware. The aim is to identify early encryption behavior, contain impacted systems, and guide responders through triage and recovery.

## 2. Scope & Preconditions
- **Environment:** Windows endpoints and file servers.
- **Data Sources:**
  - Windows Security Logs (Event ID 4663 = file access, 4688 = process creation).
  - Sysmon (Event ID 11 = file create, Event ID 1 = process creation).
  - EDR logs (Defender for Endpoint, CrowdStrike, etc.).
  - File server auditing (FSRM, NetApp/EMC).
  - Network telemetry (SMB traffic spikes).
- **Assumptions:** Endpoint coverage in place on high-value systems.

## 3. Hypothesis
> If Rhysida begins encrypting files, we will observe **high-volume file modifications** with suspicious extensions and processes creating those files.

## 4. Mappings
- **MITRE ATT&CK:** T1486 – Data Encrypted for Impact
- **Related Techniques:** T1489 (Service Stop), T1490 (Inhibit System Recovery)
- **NIST CSF:** PR.DS-5, DE.CM-7, RS.MI-1
- **CIS Controls:** 10.6, 11.1, 11.4
