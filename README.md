# 🔍 Log Analyzer & Threat Detector

A Python-based cybersecurity tool designed to analyze Apache/Nginx access logs and detect suspicious IP activity using a custom threat-scoring engine.  
This project simulates real SOC (Security Operations Center) log investigation workflows — perfect for learning threat detection fundamentals.


## ⭐ Features

- 🔎 **Suspicious IP Detection**  
  Finds brute-force attempts, scanning behavior, and abnormal patterns.

- 🚫 **Sensitive Endpoint Monitoring**  
  Flags access to `/admin`, `/login`, `wp-admin`, `/config`, etc.

- 🛑 **Suspicious HTTP Methods**  
  Detects `DELETE`, `TRACE`, `OPTIONS` requests often used in attacks.

- 📊 **Threat Scoring System**  
  Assigns severity scores based on behavior and generates reports.

- 📁 **Automatic Report Generation**  
  - `report.txt` → Full traffic summary  
  - `suspicious_ips.txt` → High-risk IPs only

