# 🛡️ OPoison

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-informational?style=flat-square&logo=linux&logoColor=white&color=0a0c10"/>
  <img src="https://img.shields.io/badge/Category-ONetwork%20%2F%20MITM%20Detection-cyan?style=flat-square"/>
  <img src="https://img.shields.io/badge/Dependencies-Scapy-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-Proprietary-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-v2.0-cyan?style=flat-square"/>
</p>

> **OPoison** is an advanced ARP spoofing and MITM detection engine. It monitors live traffic, detects ARP poisoning attacks, IP-MAC mismatches, gateway impersonation, ARP floods, and provides real-time alerts with detailed reporting.

---

## 📌 Overview

OPoison actively monitors the local network for ARP-based MITM attacks. It builds a trusted ARP baseline, detects suspicious MAC changes, identifies duplicate MACs, and continuously guards the gateway IP. It includes multiple modules for scanning, live monitoring, passive sniffing, and historical analysis.

**⚠️ LEGAL NOTICE**: Use **ONLY** on networks you own or have explicit written authorisation to monitor. Unauthorised use is illegal.

---

## 🖥️ Modules

| # | Module                  | Description |
|---|-------------------------|-------------|
| **[1]** | **Live Monitor**            | Real-time ARP spoof & MITM detection with live alerts |
| **[2]** | **ARP Network Scan**        | Discover all hosts in a subnet and detect duplicate MACs |
| **[3]** | **ARP Table Inspector**     | Inspect system ARP cache and cross-check with live scan |
| **[4]** | **Passive Traffic Sniffer** | Capture packets with custom BPF filter |
| **[5]** | **Gateway Guardian**        | Continuous protection of the gateway MAC address |
| **[6]** | **Alert History**           | View past security alerts |
| **[7]** | **Session History**         | Review previous monitoring sessions |

---

## 📊 Key Features

- **Real-time MITM Detection**: IP-MAC mismatch, Gratuitous ARP, ARP flood, Gateway impersonation
- **Risk Scoring**: 0–100 score with clear severity levels
- **Gateway Protection**: Continuous watch on the gateway MAC address
- **Live ARP Table**: Trusted baseline with suspicious highlighting
- **All Devices Tracking**: Monitors every IP seen on the network
- **Detailed Logging**: CSV and JSON export of all sessions and alerts
- **VM/Tool Detection**: Identifies common virtual machine MAC prefixes
- **Visual & Audio Alerts**: Flashing banner + bell on critical events

---

## ⚙️ Requirements

- **Linux only** (requires root privileges)
- **Scapy**: `pip install scapy`
- **Root access**: Must be run with `sudo`

---

## 🚀 Usage

```bash
sudo ./OPoison

📁 Output

Alerts: ~/.omitm_alerts.json
History: ~/.omitm_history.json
Session Logs: CSV and JSON reports saved with timestamp


📦 Part of OwlSec Toolkit
This tool is part of the OwlSec suite — a collection of 300+ security and privacy tools.
🔗 owlsec.org

©️ License
Proprietary — © Khaled S. Haddad
Tools are distributed as pre-built executables. Source code is proprietary.

AUTHORISED NETWORK MONITORING USE ONLY
