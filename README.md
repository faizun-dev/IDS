# Real-Time Intrusion Detection System (IDS) in Python

This project implements a **real-time Intrusion Detection System (IDS)** using **Python** and **Scapy** for analyzing network traffic **live** and detecting common attacks such as TCP scans, ICMP floods, and suspicious handshake patterns.

---

## Features

- **SYN Scan Detection**: Detects multiple connection attempts to different ports from a single source IP.
- **ACK / RST Monitoring**: Tracks half-open connections and unusual RST responses.
- **NULL Scan Detection**: Flags TCP packets with no flags set (potential stealth scans).
- **FIN Scan Detection**: Identifies FIN packets without prior connection context.
- **ICMP Flood Detection**: Detects excessive ping requests from a single source.
- **Real-Time Monitoring**: Continuously captures packets using Scapy.
- **Background Cleanup Thread**: Automatically removes outdated entries to maintain accuracy.
- **Logging**: Alerts are printed to the console and appended to `alert_log.txt`.



