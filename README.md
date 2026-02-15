# ICS 344 Course Project — API Security & Monitoring

This repository is the official course project package for **ICS 344 (Information Security)**. 

The project is based on **crAPI (Completely Ridiculous API)** — an intentionally vulnerable platform designed to teach real-world API security failures. Students will perform structured reconnaissance, identify and exploit vulnerabilities, and analyze attack evidence using log correlation and SIEM tools.

---

## 1) Project Context & Purpose

Modern systems increasingly rely on **APIs and microservices** instead of traditional monolithic web apps. This project is designed to build practical skills in:

- **Web Security:** Identifying authorization bypasses, injection, and logic flaws.
- **Access Control:** Auditing authentication methods and authorization models.
- **Monitoring & Detection:** Connecting offensive activity with defensive evidence.

---

## 2) Project Structure & Objectives

Each group will complete three distinct phases:

### Phase 1 — Setup & Reconnaissance
- Deploy the lab environment and map the API surface.
- **The "Happy Path":** Before attacking, you **must** follow the intended user workflow to understand normal behavior. This is critical for distinguishing between "Normal" and "Malicious" traffic in later phases. Refer to `docs/happy-path.md`.

### Phase 2 — Vulnerability Discovery & Exploitation
You must successfully exploit **six (6) unique vulnerabilities**:
- **Mandatory (3):** 
    - Challenge 1: BOLA (Vehicle Location Leak)
    - Challenge 7: BFLA (Unauthorized Administrative Action)
    - Challenge 8: Mass Assignment (Business Logic/Quantity Abuse)
- **Elective (3):** Choose any three additional challenges from the platform (e.g., JWT, SQLi, or Prompt Injection).

### Phase 3 — Logging & Detection
- Ingest traffic logs into a SIEM of your choice.
- Create searches to detect your specific attack patterns.
- Provide "Proof of Detection" (Indicators of Compromise) for your exploits.

---

## 3) Deployment Guidelines

### Baseline Setup
This repository contains a Docker-based deployment. While you are free to deploy the environment in the way that best suits your team, you must satisfy these constraints:
- The application must run locally (Docker is recommended).
- All communication should be captured and logged for analysis.

### Important Note on Networking
If you choose to integrate a reverse proxy (like Nginx) or a SIEM tool (like Splunk or ELK), you may need to modify the default port mappings in `docker-compose.yml`. Ensure your proxy is correctly routing traffic to the internal services.

---


---

## 4) Deliverables

Each group must submit a professional PDF report containing:
1. **Executive Summary:** High-level risk assessment.
2. **Vulnerability Writeups (x6):** 
    - Description, Impact, and Root Cause analysis.
    - **Proof of Exploitation:** Screenshots of request/response (Burp/ZAP).
    - **Indicator of Compromise (IoC):** SIEM screenshots or queries showing the "digital footprint" of the attack.
3. **Remediation:** Proposed code-level fixes for the vulnerabilities.

---

## 5) Academic Integrity and Ethics

- Perform attacks **ONLY** against your local lab environment.
- Do **NOT** share working exploit steps with other groups.
- Do **NOT** search for or publish solutions online.

---

## ⚖️ License & Attribution
This lab is based on the **OWASP crAPI** project. 
Copyright (c) 2021 OWASP Foundation. This project is licensed under the **Apache License 2.0**.