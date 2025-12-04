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

## 📂 Project Structure
log-analyzer-threat-detector/
│── analyzer.py
│── access.log
│── README.md
│── report.txt (generated)
│── suspicious_ips.txt (generated)

---

## ⚙️ How to Run

1️⃣ Clone the repository  
```bash
git clone https://github.com/anshsethas/log-analyzer-threat-detector
cd log-analyzer-threat-detector

2️⃣ Add your server log file:
access.log

3️⃣ Run the tool
python3 analyzer.py

4️⃣ Generated outputs:
report.txt → all IPs + request counts + threat scores
suspicious_ips.txt → only flagged malicious IPs

📌 Example Output
🔥 suspicious_ips.txt
192.168.1.10 - Score: 45
45.90.22.18  - Score: 20

📄 report.txt
IP: 192.168.1.10 | Requests: 85 | Score: 45
IP: 102.80.33.5 | Requests: 3  | Score: 0


🧠 Learning Outcomes
✔ Understand real-world log patterns
✔ Detect malicious HTTP activity
✔ Build Python automation for cybersecurity
✔ Perform SOC-style investigations
✔ Implement threat scoring & analysis logic


🚀 Future Enhancements
🌍 GeoIP lookup
📦 JSON/CSV export
📊 ELK/Splunk dashboard integration
🔁 Real-time monitoring
🧵 Multi-log directory support


👤 Author
Ansh Kumar
Cybersecurity Student | Threat Analysis | Python | IAM
📬 Contact
LinkedIn: https://www.linkedin.com/in/anshsethas/
