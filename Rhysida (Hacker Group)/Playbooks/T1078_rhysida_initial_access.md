# Playbook: Suspicious VPN Access – Rhysida (T1078)

## 1. Purpose
Detect unauthorized VPN logins using compromised credentials, a known Rhysida initial access vector.

## 2. Scope & Preconditions
- Access: External VPN log sources + identity logs.
- Infrastructure: All VPN gateways, MFA logs.
- Logging: Must capture geolocation, MFA status, IPs.

## 3. Hypothesis
"If Rhysida operators use stolen credentials, they'll authenticate over VPN from anomalous geographies or without MFA."

## 4. Mappings
- **MITRE ATT&CK**: T1078 (Valid Accounts)
- **NIST CSF**, e.g., PR.AC-1, PR.AC-4

## 5. Detections
- Sigma rule: “Suspicious VPN login…”
   title: Suspicious VPN login with potential Rhysida access
id: rhysida-vpn-access
status: experimental
description: Detects VPN logins using valid accounts from unusual geolocations or outside MFA flow.
author: you
references:
  - AA23-319A #StopRansomware: Rhysida Ransomware advisory
tags:
  - attack.t1078
logsource:
  category: authentication
  product: vpn
detection:
  selection:
    SourceGeoLocation|not_in:
      - 'United States'
    LDAPUsername|exists: true
  condition: selection
fields:
  - Timestamp
  - Username
  - SourceIP
  - SourceGeoLocation
falsepositives:
  - Traveling users
level: medium
- KQL query.

   SigninLogs
| where ResultDescription == "Success"
| where Location !in ("United States")
| where ConditionalAccessStatus != "mfa_succeeded"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ConditionalAccessStatus
- SPL query.

  index=vpn_logs action=success
| where geo_location!="United States"
| where mfa="false"
| table _time, user, src_ip, geo_location
- Tuning: Exempt known travel or proxy IPs; enrich with identity risk.

## 6. Triage & Investigation
- Check user’s recent travel.
- Was source IP suspicious (VPN chain, TOR exit)?
- Investigate other actions from host (process creation, network exec).
- Check preceding MFA logs.

## 7. Containment
- Force password reset.
- Require verification of recent MFA usage.
- Block source IP temporarily.

## 8. Eradication & Recovery
- Review similar logins 24h before/after incident.
- Enable conditional access policies (always require MFA).
- Freeze credentials if suspicious.

## 9. Communication
- Alert SOC and identity governance team.
- If confirmed, escalate to IR and legal if data access occurred.

## 10. Metrics
- Count of “VPN logins without MFA”.
- Triage latency, detection precision.

## 11. Testing
Simulate:
```powershell
# Simulated unauthorized login example: log dummy event.
