# Duo Log Ingestion Service

A **Python-based UDP Syslog Server** for ingesting and processing JSON-formatted logs from **Duo Security** events. This script listens on multiple ports for log events, normalizes incoming data, fixes malformed JSON, and removes unnecessary escape sequences before storing logs in structured `.log` files.

## 🚀 Features

- **Supports Multiple Listeners** – Configurable syslog receivers on different ports.
- **JSON Repair Mechanism** – Automatically fixes common JSON issues such as missing commas, improperly escaped characters, and truncated messages.
- **Unicode Cleaning** – Removes unnecessary escape sequences (`\`, `\n`, `\t`, `\uXXXX`) while preserving valid JSON.
- **JavaScript Code Validation** – Detects and logs invalid JavaScript found in log entries.
- **Separate Storage for Malformed Logs** – Saves unfixable logs in a separate `invalid_logs/` directory for debugging.

---

## 📥 Installation

### **Requirements**
- Python 3.8+
- Required libraries: `execjs`

### **Setup Instructions**
```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/duo-log-ingest.git
cd duo-log-ingest

# Install required Python packages
pip install execjs
```

---

## ⚙️ Configuration

Modify the `LISTENERS` dictionary in `log-ingest.py` to define the **listener names and ports**:

```python
LISTENERS = [
    {"name": "duo-adminaction", "port": 5140},
    {"name": "duo-auth", "port": 5141},
    {"name": "duo-activity", "port": 5142},
    {"name": "duo-trustmonitor", "port": 5143},
    {"name": "duo-telephony", "port": 5144},
]
```

---

## 🚀 Usage

Run the log ingestion service:
```bash
python log-ingest.py
```

The script will start listening on the specified ports and print incoming logs to the console while also writing them to log files.

### **Sending a Test Log**
Use **Netcat (`nc`)** to send a test log entry:
```bash
echo '{"isotimestamp": "2025-02-19T15:00:00Z", "event": "test_event"}' | nc -u -w1 127.0.0.1 5141
```

---

## 📂 Log Storage
- **Valid logs** are stored in `logs/` with filenames matching the listener name and date:
  ```
  logs/duo-auth_YYYY-MM-DD.log
  ```
- **Invalid JSON logs** (unfixable) are stored in `invalid_logs/`:
  ```
  invalid_logs/duo-auth_invalid_json_YYYY-MM-DD.log
  ```
- **Invalid JavaScript logs** are stored separately:
  ```
  invalid_logs/duo-auth_invalid_js_YYYY-MM-DD.log
  ```

---

## 🛠️ Troubleshooting

### **Issue: "Error: Expecting ',' delimiter"**
📌 **Cause:** Malformed JSON logs with missing commas or escape issues.
✅ **Solution:** The script attempts to fix these issues automatically. If a log cannot be fixed, check `invalid_logs/` for details.

### **Issue: "Unicode escape error"**
📌 **Cause:** Malformed Unicode escape sequences (`\uXXXX`).
✅ **Solution:** Unicode escapes are now safely handled. Logs with persistent errors will be stored in `invalid_logs/` for debugging.

### **Issue: "Some logs still contain backslashes"**
📌 **Cause:** Nested JSON-encoded strings within log fields.
✅ **Solution:** The script now recursively decodes these fields before storing logs.

---

## 📜 License
This project is licensed under the **MIT License**.

---

*Note: This README was auto-generated by GPT-4o

