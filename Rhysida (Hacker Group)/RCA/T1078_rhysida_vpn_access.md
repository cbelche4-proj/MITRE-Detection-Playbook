# RCA: Rhysida VPN Initial Access via Valid Accounts (T1078)

## Summary
VPN login from unusual geolocation without MFA checked flags detection.

## Timeline
- **T0**: Alert triggered from Sigma/KQL rule.
- **T1**: Identify user account, source IP, location.
- **T2**: Verify if password was compromised or phishing occurred.
- **T3**: Block IP, reset credentials, enforce MFA.

## Affected Scope
- User account.
- VPN logs (time, IP).
- Downstream process / network activity.

## Root Cause
- MFA not required.
- No geo-based access policy.

## Contributing Factors
- Legacy VPN configuration.
- Weak identity policy.

## Containment
- Credential reset at T2.
- Temporary access revocation.

## Eradication & Recovery
- Enforce conditional access.
- Review similar-lo events.

## Evidence
- Logs, IPs, timestamps, rule triggered.

## Preventive Actions
- Enforce phishing-resistant MFA.
- Geo-blocking or prompt on anomalous locations.
- Alerts for logins without MFA.

## Metrics
- Time to detect/log alert.
- MFA bypass attempts.
