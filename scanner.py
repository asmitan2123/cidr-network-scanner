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

# ─────────────────────────────────────────────
# Common ports to scan (name → port number)
# ─────────────────────────────────────────────
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


# ─────────────────────────────────────────────
# Step 1: Ping host to check if it's alive
# ─────────────────────────────────────────────
def is_host_alive(ip: str) -> bool:
    """
    Sends one ICMP ping to check if the host is alive.
    Automatically uses the correct ping flags for Windows or Linux/Mac.
    """
    try:
        # Windows uses -n for count and -w for timeout (in milliseconds)
        # Linux/Mac uses -c for count and -W for timeout (in seconds)
        if sys.platform == "win32":
            cmd = ["ping", "-n", "1", "-w", "1000", str(ip)]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", str(ip)]

        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
        return result.returncode == 0
    except Exception:
        return False


# ─────────────────────────────────────────────
# Step 2: Scan a single port on a host
# ─────────────────────────────────────────────
def scan_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    """
    Tries to connect to a TCP port.
    Returns True if the port is open, False otherwise.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


# ─────────────────────────────────────────────
# Step 3: Scan all common ports for one IP
# ─────────────────────────────────────────────
def scan_host_ports(ip: str, ports: dict) -> list:
    """
    Scans all given ports for an IP address.
    Returns list of dicts with open port info.
    """
    open_ports = []
    for port, service in ports.items():
        if scan_port(ip, port):
            open_ports.append({"port": port, "service": service, "state": "open"})
    return open_ports


# ─────────────────────────────────────────────
# Step 4: Scan entire subnet
# ─────────────────────────────────────────────
def scan_subnet(cidr: str, max_workers: int = 50) -> dict:
    """
    Main scanning function.
    1. Parses the CIDR range
    2. Pings each IP in parallel
    3. Port-scans all live hosts
    Returns a structured results dictionary.
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

    # ── Ping sweep in parallel ──
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(is_host_alive, str(ip)): str(ip) for ip in all_ips}
        for i, future in enumerate(as_completed(futures), 1):
            ip = futures[future]
            alive = future.result()
            print(f"  [{i}/{total}] {ip} → {'ALIVE ✓' if alive else 'dead'}", end="\r")
            if alive:
                live_ips.append(ip)

    print(f"\n\n[+] Found {len(live_ips)} live host(s). Starting port scan...\n")

    # ── Port scan each live host ──
    results = []
    for ip in live_ips:
        print(f"  [*] Port scanning {ip} ...")
        open_ports = scan_host_ports(ip, COMMON_PORTS)

        # Try to resolve hostname
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = "N/A"

        results.append(
            {
                "ip": ip,
                "hostname": hostname,
                "status": "alive",
                "open_ports": open_ports,
                "total_open": len(open_ports),
            }
        )

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


# ─────────────────────────────────────────────
# Step 5: Save JSON output
# ─────────────────────────────────────────────
def save_json(data: dict, output_path: str):
    with open(output_path, "w") as f:
        json.dump(data, f, indent=4)
    print(f"\n[+] JSON report saved: {output_path}")


# ─────────────────────────────────────────────
# Step 6: Generate Markdown report
# ─────────────────────────────────────────────
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
                lines.append("_No open ports detected from the common port list._")

            lines.append("")
            lines.append("---")
            lines.append("")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"[+] Markdown report saved: {output_path}")


# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="CIDR Subnet Scanner — Find live hosts and open ports",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python scanner.py 192.168.1.0/24
  python scanner.py 10.0.0.0/28 --output-dir results/
  python scanner.py 172.16.0.0/24 --workers 100
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
        default=50,
        help="Number of parallel threads for ping sweep (default: 50)",
    )

    args = parser.parse_args()

    # Create output directory
    Path(args.output_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = f"{args.output_dir}/scan_{timestamp}.json"
    md_path = f"{args.output_dir}/scan_{timestamp}.md"

    # Run scan
    scan_data = scan_subnet(args.cidr, max_workers=args.workers)

    # Save outputs
    save_json(scan_data, json_path)
    save_markdown(scan_data, md_path)

    print(f"\n[+] Scan complete! Results saved to '{args.output_dir}'")


if __name__ == "__main__":
    main()
