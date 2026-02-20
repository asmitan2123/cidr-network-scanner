# 🔍 CIDR Network Scanner

A lightweight Python tool that scans a network subnet (CIDR range), identifies **live hosts**, performs **port scanning**, and generates both a **JSON file** and a **Markdown report**.

---

## 📌 Features

- ✅ Accepts any valid CIDR range (e.g. `192.168.1.0/24`)
- ✅ Ping sweep to detect live hosts (parallel, fast)
- ✅ TCP port scan on 17 common ports
- ✅ Hostname resolution for each live host
- ✅ Output in **JSON** format (machine-readable)
- ✅ Output in **Markdown** format (human-readable report)
- ✅ Dockerized for easy deployment
- ✅ Zero external dependencies (pure Python standard library)

---

## 🚀 Quick Start

### Option 1: Run with Python (Recommended for beginners)

**Step 1 — Clone the repository:**
```bash
git clone https://github.com/YOUR_USERNAME/cidr-network-scanner.git
cd cidr-network-scanner
```

**Step 2 — Run the install script:**
```bash
bash install.sh
```

**Step 3 — Scan a network:**
```bash
python3 scanner.py 192.168.1.0/24
```

---

### Option 2: Run with Docker

**Build the image:**
```bash
docker build -t cidr-scanner .
```

**Run a scan:**
```bash
docker run --rm \
  --network host \
  -v $(pwd)/output:/app/output \
  cidr-scanner 192.168.1.0/24
```

> **Note:** `--network host` is required so the container can reach your local network.

---

## 🛠️ Usage

```
python3 scanner.py <CIDR> [OPTIONS]
```

| Argument        | Description                                      | Default     |
|----------------|--------------------------------------------------|-------------|
| `cidr`          | Target network in CIDR notation (**required**)   | —           |
| `--output-dir`  | Folder to save results                           | `./output/` |
| `--workers`     | Number of parallel threads for ping sweep        | `50`        |

---

## 📖 Usage Examples

**Scan a /24 subnet:**
```bash
python3 scanner.py 192.168.1.0/24
```

**Scan a small /28 subnet and save to custom folder:**
```bash
python3 scanner.py 10.0.0.0/28 --output-dir my_results/
```

**Use more threads for faster scanning:**
```bash
python3 scanner.py 172.16.0.0/24 --workers 100
```

**Get help:**
```bash
python3 scanner.py --help
```

---

## 📁 Output Files

After each scan, two files are saved in the `output/` directory:

### 1. JSON File (`scan_YYYYMMDD_HHMMSS.json`)
Machine-readable structured data. Example:

```json
{
    "scan_info": {
        "target": "192.168.1.0/24",
        "total_hosts_scanned": 254,
        "live_hosts_found": 3,
        "timestamp": "2026-02-20T14:30:00",
        "ports_checked": 17
    },
    "results": [
        {
            "ip": "192.168.1.1",
            "hostname": "router.local",
            "status": "alive",
            "open_ports": [
                {"port": 80, "service": "HTTP", "state": "open"},
                {"port": 443, "service": "HTTPS", "state": "open"}
            ],
            "total_open": 2
        }
    ]
}
```

### 2. Markdown File (`scan_YYYYMMDD_HHMMSS.md`)
Human-readable report with tables and formatting. Can be viewed in any Markdown viewer or GitHub.

---

## 🔌 Ports Scanned

| Port  | Service     |
|-------|-------------|
| 21    | FTP         |
| 22    | SSH         |
| 23    | Telnet      |
| 25    | SMTP        |
| 53    | DNS         |
| 80    | HTTP        |
| 110   | POP3        |
| 143   | IMAP        |
| 443   | HTTPS       |
| 445   | SMB         |
| 3306  | MySQL       |
| 3389  | RDP         |
| 5432  | PostgreSQL  |
| 6379  | Redis       |
| 8080  | HTTP-Alt    |
| 8443  | HTTPS-Alt   |
| 27017 | MongoDB     |

---

## 🧰 How It Works

```
Input CIDR
    │
    ▼
Parse all IPs in the range
    │
    ▼
Ping Sweep (parallel threads)
    │
    ▼
Filter: Live Hosts Only
    │
    ▼
TCP Port Scan (each live host)
    │
    ▼
Hostname Resolution
    │
    ├──► JSON Output
    └──► Markdown Report
```

---

## 📋 Requirements

- Python 3.8+
- Linux or macOS (for `ping` command)
- Root/sudo may be required on some systems for ICMP ping

---

## ⚠️ Legal Disclaimer

> This tool is intended for **educational purposes** and **authorized network scanning only**.  
> Always ensure you have **explicit permission** before scanning any network.  
> Unauthorized scanning may be illegal in your jurisdiction.

---

## 📄 License

MIT License — Free to use, modify, and distribute.
