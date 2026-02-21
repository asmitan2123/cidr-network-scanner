# CIDR Network Scanner

A Python tool that scans a network subnet (CIDR range), finds live hosts, scans their ports, and generates a JSON file and a Markdown report.

---

## Features

- Accepts any valid CIDR range (e.g. 192.168.1.0/24)
- Ping sweep to detect live hosts (runs in parallel for speed)
- TCP port scan on 17 common ports
- Hostname resolution for each live host
- Output in JSON format (machine-readable)
- Output in Markdown format (human-readable report)
- Works on Windows, Linux, and Mac
- Dockerized for easy deployment
- No external dependencies (pure Python standard library)

---

## Demo Video

https://drive.google.com/file/d/1JOPWzaTRp0G0d_FlJVTQXlNk9heO5d7V/view?usp=sharing

---

## Quick Start

### Option 1: Run with Python

Step 1 - Clone the repository:
```
git clone https://github.com/YOUR_USERNAME/cidr-network-scanner.git
cd cidr-network-scanner
```

Step 2 - Run a scan:
```
python scanner.py 192.168.1.0/24
```

---

### Option 2: Run with Docker

Build the image:
```
docker build -t cidr-scanner .
```

Run a scan:
```
docker run --rm --network host -v $(pwd)/output:/app/output cidr-scanner 192.168.1.0/24
```

---

## Usage

```
python scanner.py <CIDR> [OPTIONS]
```

| Argument       | Description                              | Default     |
|----------------|------------------------------------------|-------------|
| cidr           | Target network in CIDR notation          | (required)  |
| --output-dir   | Folder to save results                   | ./output/   |
| --workers      | Number of parallel threads               | 50          |

---

## Usage Examples

Scan a /24 subnet:
```
python scanner.py 192.168.1.0/24
```

Save results to a custom folder:
```
python scanner.py 10.0.0.0/28 --output-dir my_results/
```

Use more threads for faster scanning:
```
python scanner.py 172.16.0.0/24 --workers 100
```

---

## Output Files

After each scan, two files are saved in the output/ directory:

### JSON File (scan_YYYYMMDD_HHMMSS.json)

```json
{
    "scan_info": {
        "target": "192.168.1.0/24",
        "total_hosts_scanned": 254,
        "live_hosts_found": 3,
        "timestamp": "2026-02-21T14:30:00",
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

### Markdown File (scan_YYYYMMDD_HHMMSS.md)

Human-readable report with tables. Can be viewed on GitHub directly.

---

## Ports Scanned

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

## How It Works

1. Parse all IP addresses from the CIDR range
2. Ping every IP in parallel to find live hosts
3. For each live host, attempt TCP connection on 17 common ports
4. Resolve hostname for each live host
5. Save results as JSON and Markdown

---

## Requirements

- Python 3.8 or higher
- Works on Windows, Linux, and macOS

---

## Legal Disclaimer

This tool is for educational purposes and authorized network scanning only.
Always ensure you have permission before scanning any network.
