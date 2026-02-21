#!/usr/bin/env python3
"""
CIDR Network Scanner
Scans a subnet for live hosts and open ports, outputs JSON + Markdown report.
"""

import argparse
import json
import socket
import subprocess
import sys
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Common ports to scan
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


def is_host_alive(ip: str) -> bool:
    """
    Checks if a host is alive by trying to connect to common ports.
    Works on Windows even when ICMP ping is blocked by firewall.
    """
    quick_ports = [80, 443, 445, 22, 3389, 8080, 21, 23, 53]
    for port in quick_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0 or result in (111, 10061):
                return True
        except Exception:
            pass

    try:
        if sys.platform == "win32":
            cmd = ["ping", "-n", "1", "-w", "500", str(ip)]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", str(ip)]
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )
        return result.returncode == 0
    except Exception:
        return False


def scan_port(ip: str, port: int, timeout: float = 0.3) -> bool:
    """
    Tries to connect to a TCP port.
    Returns True if the port is open, False otherwise.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def scan_host_ports(ip: str, ports: dict) -> list:
    """
    Scans all ports for one IP in parallel - much faster!
    """
    open_ports = []

    def check(port_service):
        port, service = port_service
        if scan_port(ip, port):
            return {"port": port, "service": service, "state": "open"}
        return None

    with ThreadPoolExecutor(max_workers=17) as executor:
        results = executor.map(check, ports.items())

    for r in results:
        if r:
            open_ports.append(r)

    return open_ports


def scan_subnet(cidr: str, max_workers: int = 100) -> dict:
    """
    Main scanning function.
    1. Parses the CIDR range
    2. Checks each IP in parallel
    3. Port-scans all live hosts in parallel
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        print(f"[ERROR] Invalid CIDR: {e}")
        sys.exit(1)

    all_ips = list(network.hosts())
    total = len(all_ips)
    print(f"\n[*] Scanning {cidr} ({total} hosts) ...")
    print(f"[*] Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    live_ips = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(is_host_alive, str(ip)): str(ip) for ip in all_ips}
        for i, future in enumerate(as_completed(futures), 1):
            ip = futures[future]
            alive = future.result()
            print(f"  [{i}/{total}] Checking {ip} ...", end="\r")
            if alive:
                live_ips.append(ip)

    print(f"\n\n[+] Found {len(live_ips)} live host(s). Starting port scan...\n")

    results = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        def scan_one(ip):
            print(f"  [*] Port scanning {ip} ...")
            open_ports = scan_host_ports(ip, COMMON_PORTS)
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                hostname = "N/A"
            return {
                "ip": ip,
                "hostname": hostname,
                "status": "alive",
                "open_ports": open_ports,
                "total_open": len(open_ports),
            }
        results = list(executor.map(scan_one, live_ips))

    scan_data = {
        "scan_info": {
            "target": cidr,
            "total_hosts_scanned": total,
            "live_hosts_found": len(live_ips),
            "timestamp": datetime.now().isoformat(),
            "ports_checked": len(COMMON_PORTS),
        },
        "results": results,
    }

    return scan_data


def save_json(data: dict, output_path: str):
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    print(f"\n[+] JSON report saved: {output_path}")


def save_markdown(data: dict, output_path: str):
    info = data["scan_info"]
    results = data["results"]

    lines = [
        "# Network Scan Report",
        "",
        "## Scan Summary",
        "",
        f"| Field              | Value |",
        f"|-------------------|-------|",
        f"| **Target CIDR**   | `{info['target']}` |",
        f"| **Scan Time**     | {info['timestamp']} |",
        f"| **Hosts Scanned** | {info['total_hosts_scanned']} |",
        f"| **Live Hosts**    | {info['live_hosts_found']} |",
        f"| **Ports Checked** | {info['ports_checked']} |",
        "",
        "---",
        "",
        "## Live Hosts and Open Ports",
        "",
    ]

    if not results:
        lines.append("_No live hosts found._")
    else:
        for host in results:
            lines.append(f"### Host: {host['ip']} -- {host['hostname']}")
            lines.append("")
            lines.append(f"- **Status:** {host['status'].upper()}")
            lines.append(f"- **Open Ports:** {host['total_open']}")
            lines.append("")

            if host["open_ports"]:
                lines.append("| Port | Service | State |")
                lines.append("|------|---------|-------|")
                for p in host["open_ports"]:
                    lines.append(f"| {p['port']} | {p['service']} | OPEN |")
            else:
                lines.append("_No open ports detected._")

            lines.append("")
            lines.append("---")
            lines.append("")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"[+] Markdown report saved: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="CIDR Subnet Scanner - Find live hosts and open ports",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python scanner.py 192.168.1.0/24
  python scanner.py 10.0.0.0/28 --output-dir results/
  python scanner.py 30.10.1.0/24 --workers 100
        """,
    )
    parser.add_argument("cidr", help="Target subnet in CIDR notation (e.g. 192.168.1.0/24)")
    parser.add_argument(
        "--output-dir",
        default="output",
        help="Directory to save reports (default: ./output)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=100,
        help="Number of parallel threads (default: 100)",
    )

    args = parser.parse_args()

    Path(args.output_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = f"{args.output_dir}/scan_{timestamp}.json"
    md_path = f"{args.output_dir}/scan_{timestamp}.md"

    scan_data = scan_subnet(args.cidr, max_workers=args.workers)

    save_json(scan_data, json_path)
    save_markdown(scan_data, md_path)

    print(f"\n[+] Scan complete! Results saved to '{args.output_dir}'")


if __name__ == "__main__":
    main()
