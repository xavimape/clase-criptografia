🌐 Spanish version: [README.md](README.md)

# Cryptography for SOC Analysts

## Overview

This repository offers a practical introduction to cryptography applied in real security analysis contexts. The material combines conceptual foundations, functional Python implementations, and analysis cases based on situations a SOC analyst may encounter in daily work.

The approach is applied: each topic is connected to a concrete scenario, a detection technique, or a real response decision.

---

## Learning Focus

- Identify encoded and encrypted data in real-world network traffic scenarios
- Understand how hashing algorithms are used and abused in authentication systems
- Recognize weak or poorly implemented cryptographic practices and their security impact
- Analyze TLS session anomalies through JA3 fingerprinting
- Interpret ransomware behavior from a technical and forensic perspective
- Map offensive techniques to the MITRE ATT&CK framework
- Develop analytical judgment to classify and prioritize threats

---

## Project Structure

```
/teoria           → Cryptography concepts explained from a SOC analyst perspective
/implementaciones → Runnable Python scripts illustrating encoding, hashing, AES, and RSA
/ejercicios       → Practical activities organized across three increasing difficulty levels
/tools            → Interactive tool with analysis console, CTF lab, and reference sheet
/cases            → SOC analysis cases with real logs, MITRE ATT&CK mapping, and analyst verdict
/lab              → Additional exercises with guided structure
```

---

## Analysis Scenarios

Each case includes an event log, a complete technical analysis, and a conclusion with an analyst verdict. The goal is to practice the investigation process, not arrive at a predetermined answer.

### Case 01 — Base64 Exfiltration
HTTP request with a Base64-encoded parameter sent to a suspicious domain via curl. The exercise focuses on identifying exfiltration indicators and analyzing basic evasion techniques.

### Case 02 — Weak Hash Detection
Authentication attempt using an MD5 hash of a trivial password (`password`) from an internal IP. The focus is on assessing the risk of weak algorithms in authentication systems and evaluating secure alternatives.

### Case 03 — TLS Anomaly
TLS session with a self-signed certificate and anomalous JA3 fingerprint toward anonymous infrastructure. The exercise covers detecting potential encrypted C2 channels through TLS metadata analysis.

### Case 04 — Ransomware Activity
Active ransomware event with mass file encryption, shadow copy deletion, AV disabling, and outbound connection. The focus is on analyzing the behavioral chain and working through containment and response decisions.

---

## Tools & Techniques

| Area                  | Tools / Concepts                                  |
|-----------------------|---------------------------------------------------|
| Encoding              | Base64, Hex, URL encoding, CyberChef              |
| Hashing               | MD5, SHA-1, SHA-256, HMAC, rainbow tables         |
| Symmetric encryption  | AES-CBC, AES-GCM, IV reuse vulnerability          |
| Asymmetric encryption | RSA-2048, PKCS1_OAEP, PSS digital signatures      |
| TLS inspection        | JA3/JA3S fingerprinting, Wireshark, SNI analysis  |
| Password auditing     | John the Ripper (forensic context)                |
| Threat Intelligence   | MITRE ATT&CK, IOC classification, TIP integration |

---

## How to Use

1. Open `index.html` in a browser to access the main panel.
2. Navigate to `/tools/crypto-demo.html` for the interactive demo with console and CTF lab.
3. Review cases under `/cases/` — each includes logs, full analysis, and a conclusion with analyst verdict.
4. Run scripts under `/implementaciones/` with Python 3 + pycryptodome.

```bash
pip install pycryptodome
python implementaciones/03_aes.py
```

---

## Target Roles

This material is intended for those working or training in roles such as SOC analysis, threat intelligence, and digital forensics. It is also useful for any security professional looking to deepen their understanding of the cryptographic dimension of defensive work.

---

## Notes

- Educational project focused on real-world applicability in SOC environments.
- All cases are based on real threat patterns documented in MITRE ATT&CK.
- Python scripts are functional and executable in a local environment.

---

**Author**: [@xavimape](https://github.com/xavimape)
