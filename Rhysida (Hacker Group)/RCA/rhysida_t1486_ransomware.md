# RCA: Rhysida Ransomware Encryption (T1486)

## Summary
On Aug 25, 2025, multiple hosts began generating alerts for suspicious file modifications with the `.rhysida` extension. EDR and SIEM confirmed mass file encryption activity consistent with Rhysida ransomware.

## Timeline (UTC)
- 13:02: SIEM alert fired on high-volume file modifications.
- 13:05: SOC analyst confirmed suspicious extensions and isolated host HR-SRV01.
- 13:15: Additional hosts (FS-SRV02, ENG-SRV03) flagged similar activity.
- 13:20: Incident escalated to Incident Response team.
- 13:45: Malware samples collected, hashes blocked in EDR.
- 14:30: Backups validated for recovery.

## Affected Scope
- 3 Windows servers (HR-SRV01, FS-SRV02, ENG-SRV03).
- Approx. 12,000 files encrypted across SMB shares.

## Root Cause
- Compromised domain account used to deploy ransomware via RDP.
- MFA was not enabled on RDP access for service accounts.

## Contributing Factors
- Incomplete coverage of EDR on all file servers.
- Lack of conditional access controls for privileged accounts.

## Containment
- Isolated infected servers at switch port level.
- Disabled compromised account.
- Blocked known IoCs in firewall and EDR.

## Eradication & Recovery
- Removed ransomware executables from affected systems.
- Restored encrypted files from last night’s backup.
- Rebuilt HR-SRV01 due to integrity concerns.

## Evidence
- SHA256 hash: abc123… (Rhysida sample).
- Sysmon Event ID 11 showing `.rhysida` file creation.
- SIEM query output attached.

## Preventive Actions
- Enforce MFA on all remote access accounts.
- Apply principle of least privilege to service accounts.
- Enhance backup cadence with offline storage.
- Deploy honeypot detection for early ransomware behavior.

## Metrics
- MTTD: 3 minutes
- MTTR: 5 hours
- False Positives: 0 (all true Rhysida activity)
