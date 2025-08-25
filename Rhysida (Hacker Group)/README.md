# Overview — Rhysida (Ransomware‑as‑a‑Service)

**Rhysida** is a Ransomware‑as‑a‑Service (RaaS) group active since **May 2023**, with victims observed across **education, healthcare, manufacturing, IT, and government** sectors. It is frequently linked to **double‑extortion** operations.  
**Sources:** [CISA AA23‑319A (PDF, 2025-04 update)](https://www.cisa.gov/sites/default/files/2025-04/aa23-319a-stopransomware-rhysida-ransomware_2.pdf), [CISA advisory page](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-319a)

Rhysida exhibits **TTP overlaps with Vice Society (DEV‑0832)**, including infrastructure and operational patterns.  
**Sources:** [Sophos](https://news.sophos.com/en-us/2023/11/10/vice-society-and-rhysida-ransomware/), [CISA AA23‑319A (PDF)](https://www.cisa.gov/sites/default/files/2025-04/aa23-319a-stopransomware-rhysida-ransomware_2.pdf)

---

## MITRE ATT&CK Mapping (selected)

- **T1078 – Valid Accounts**  
  Initial access via compromised credentials (e.g., VPN logins without MFA or from anomalous sources).  
  _Source:_ [CISA AA23‑319A (PDF)](https://www.cisa.gov/sites/default/files/2025-04/aa23-319a-stopransomware-rhysida-ransomware_2.pdf)

- **T1190 – Exploit Public‑Facing Application**  
  Reported exploitation of exposed services and enterprise apps as part of intrusion chains.  
  _Source:_ [CISA AA23‑319A (PDF)](https://www.cisa.gov/sites/default/files/2025-04/aa23-319a-stopransomware-rhysida-ransomware_2.pdf)

- **“Living off the Land” (multiple techniques)**  
  Use of **RDP/VPN**, **PowerShell**, and **hidden windows** to blend in and move laterally.  
  _Sources:_ [CISA advisory page](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-319a), [CISA AA23‑319A (PDF)](https://www.cisa.gov/sites/default/files/2025-04/aa23-319a-stopransomware-rhysida-ransomware_2.pdf)

- **T1219 – Remote Access Software**  
  **AnyDesk** used for remote access and persistence.  
  _Source:_ [CISA AA23‑319A (PDF)](https://www.cisa.gov/sites/default/files/2025-04/aa23-319a-stopransomware-rhysida-ransomware_2.pdf)

- **T1486 – Data Encrypted for Impact**  
  File encryption reported using **ChaCha20** with **4096‑bit RSA** keys; typical **double‑extortion** playbook.  
  _Sources:_ [CISA AA23‑319A (PDF)](https://www.cisa.gov/sites/default/files/2025-04/aa23-319a-stopransomware-rhysida-ransomware_2.pdf), [HHS HC3](https://www.hhs.gov/sites/default/files/rhysida-ransomware-sector-alert-tlpclear.pdf), [Trend Micro](https://www.trendmicro.com/en_us/research/23/h/an-overview-of-the-new-rhysida-ransomware.html)
