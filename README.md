# 🦉 OPoison

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-ONetwork-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-Proprietary-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OPoison** — Detect ARP poisoning and MITM attacks: live monitor, ARP scan, baseline and gateway guardian

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

OPoison is an ARP spoofing and man-in-the-middle detection engine for Linux. It combines live network monitoring, ARP scanning, traffic sniffing and gateway protection to detect and alert on poisoning attempts, and supports forensics and reporting.

---

## ✨ Features

- Live monitor that detects ARP spoofing and MITM activity
- ARP scanning of the local network
- Traffic sniffer for inspecting network activity
- Gateway Guardian mode to watch the default gateway
- Alerting and forensic reporting of detections
- Offline sandboxed self-test

---

## ⚙️ Requirements

- **Linux**
- **No Python installation needed** — runs as a standalone executable

---

## 🚀 Usage

```bash
./OPoison --monitor
./OPoison --scan
./OPoison --guardian
./OPoison --help
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 275+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

Proprietary — © 2026 Owlsec LLC. All rights reserved.

*Tools are distributed as pre-built executables. Source code is proprietary.*
