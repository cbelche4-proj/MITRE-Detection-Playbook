# Playbook: <Technique Name> (<ATT&CK ID>)

## 1. Purpose
- What threat behavior are we detecting/responding to?
- Example scenario in plain English.

## 2. Scope & Preconditions
- Environments: Windows endpoints / AD / Cloud?
- Data sources required (event IDs, product tables, connectors).
- Logging coverage assumptions (e.g., Sysmon v13 with EventCode 1, 3, 11; Windows 4688; MDE Device* tables).

## 3. Hypothesis
"If an attacker <behavior>, we will observe <signals> in <logs>."

## 4. Mappings
- ATT&CK: Txxxx (tactic), sub-techniques as applicable.
- NIST CSF / CIS (optional).
- D3FEND (optional).

## 5. Detections
- Link to rules (KQL, SPL, Sigma).
- Tuning guidance (allowed apps, admin tools).
- False positive notes.

## 6. Triage & Investigation
- Immediate questions to ask (who/what/where/when/how).
- Enrichment queries (host, user, parent process, network destinations, file hashes).
- Artifacts to collect (memory, prefetch, AMCache, SRUM, firewall logs, proxy).

## 7. Containment
- Short‑term actions (isolate host, block domain/IP, kill process).
- Stakeholders (SOC, IR, IT ops).

## 8. Eradication & Recovery
- Remove persistence, remediate GPO/startup, reimage if needed.
- Patch, AV signatures, EDR policies.

## 9. Communication
- Internal updates and escalation thresholds.
- External notifications (legal, privacy) if required.

## 10. Metrics
- MTTD/MTTR targets.
- Alert volume, precision (TP/FP), coverage (hosts with needed logs).

## 11. Testing
- How to simulate (safe commands), expected log artifacts.
- Unit tests (saved searches), data replay notes.

## 12. References
- Vendor docs, ATT&CK pages, blog posts (add links).
