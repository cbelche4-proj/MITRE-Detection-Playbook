# Play Ransomware – Rapid Response Playbook


**Scenario**: Double‑extortion ransomware using valid accounts or public‑facing exploit; living‑off‑the‑land; WinRAR + WinSCP exfil; encryption with `.PLAY` extension.
**Scope**: Windows, ESXi; logs: MDE (DeviceProcessEvents), Windows Security/System, EDR, VPN/RDP, IIS/Exchange (if applicable).
**Priority**: P1


## Triggers
- KQL: WinRAR archive creation followed by WinSCP execution (same user/host)
- Sigma: Service install of **PSEXESVC** (PsExec) on endpoints


## Immediate Actions (0–15m)
1. Isolate affected hosts (EDR network containment), disable compromised accounts.
2. Capture volatile data (EDR triage package), preserve logs (disable auto‑purge; copy Security, System, Microsoft‑Windows‑Eventlog/Operational).
3. Snapshot evidence and gather ransom note, file extensions, and new services.


## Investigation (15–60m)
- **Questions**: How did initial access occur (Valid Accounts vs. Exploit Public‑Facing App vs. RMM exploit)? Is lateral movement via PsExec/GPO present? What was exfil path?
- **Pivot data**: New services (7045), Event ID 1102 (log clear), PowerShell usage, archive creation, WinSCP sessions, VPN/RDP logins, GPO changes.
- **Hunt**: Tools: AdFind, WinPEAS, GMER/IOBit/PowerTool, Mimikatz; SystemBC/Cobalt Strike beacons; ESXi commands if VMware.


## Containment / Eradication / Recovery
- Disable newly created accounts; rotate credentials/keys; remove persistence & RDP exposures; block exfil destinations; clean PsExec service; patch exploited edge devices/apps.
- Restore from known‑good backups; monitor for re‑encryption; rotate secrets; add hardening (ASR rules; PowerShell CL & Script Block Logging).


## Communications
- Notify leadership, legal, and PR; consider reporting to CISA/FBI. Maintain incident ticket and timeline.


## MITRE ATT&CK (observed/covered)
- T1078 Valid Accounts; T1190 Exploit Public‑Facing App; T1133 External Remote Services; T1059.001 PowerShell; T1016 Network Discovery; T1518.001 Security Software Discovery; T1562.001 Impair Defenses; T1070.001 Clear Windows Event Logs; T1003 OS Credential Dumping; T1570 Lateral Tool Transfer; T1484.001 Domain Policy Modification; T1560.001 Archive via Utility; T1048 Exfiltration over Alt. Protocol; T1486 Data Encrypted for Impact; T1657 Financial Theft (double‑extortion).


## Evidence
- Screenshots: alerts, queries, ransom note; `Screenshots/`
- Navigator layer: `Navigator/layer.json`
