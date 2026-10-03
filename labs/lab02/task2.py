"""Модуль для сканування доступності мережевих вузлів та портів."""

import csv
import json
import logging
import re
import socket
import time
from dataclasses import dataclass
from pathlib import Path

MAX_PORT = 65535

KNOWN_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-ALT",
}


@dataclass
class HostScanResult:
    """Результат сканування вузла."""

    host: str
    port: int
    service: str
    status: str
    response_time_ms: float
    notes: str


def validate_target(host: str, port: int) -> bool:
    """Валідація синтаксису IP або доменного імені та порту."""
    if not isinstance(port, int) or not (1 <= port <= MAX_PORT):
        return False

    ip_pattern = (
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )

    domain_pattern = (
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$|^localhost$"
    )

    return bool(re.match(ip_pattern, host) or re.match(domain_pattern, host))


def scan_host(host: str, port: int, timeout: float) -> HostScanResult:
    """Симуляція та перевірка мережевого з'єднання."""
    service_name = KNOWN_PORTS.get(port, "UNKNOWN")

    if not validate_target(host, port):
        return HostScanResult(
            host=host,
            port=port,
            service=service_name,
            status="INVALID",
            response_time_ms=0.0,
            notes="Invalid host or port format",
        )

    start_time = time.perf_counter()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.close()
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return HostScanResult(
            host=host,
            port=port,
            service=service_name,
            status="ONLINE",
            response_time_ms=round(elapsed_ms, 1),
            notes="OK",
        )
    except TimeoutError:
        return HostScanResult(
            host=host,
            port=port,
            service=service_name,
            status="OFFLINE",
            response_time_ms=0.0,
            notes="Connection timed out",
        )
    except Exception as e:
        return HostScanResult(
            host=host,
            port=port,
            service=service_name,
            status="OFFLINE",
            response_time_ms=0.0,
            notes=f"Connection failed ({type(e).__name__})",
        )


def run_scanner(
    targets_file: str,
    timeout: float,
    out_csv: str | None,
    verbose: bool,
) -> None:
    """Запуск процесу сканування та формування звіту."""
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=log_level, format="[%(levelname)s] %(message)s")

    path = Path(targets_file)
    if not path.exists():
        logging.error(f"Файл цілей {targets_file} не знайдено.")
        return

    logging.info(
        "Starting service availability scan from target list "
        f"{targets_file}...",
    )

    try:
        with open(path, encoding="utf-8") as f:
            targets = json.load(f)
    except Exception as e:
        logging.error(f"Помилка читання JSON файлу: {e}")
        return

    results: list[HostScanResult] = []

    print(
        "\nTarget Host        Port    Service    Status     "
        "Response Time  Notes",
    )
    print("-" * 75)

    for item in targets:
        host = item.get("host", "")
        port = item.get("port", 0)

        res = scan_host(host, port, timeout)
        results.append(res)

        time_str = (
            f"{res.response_time_ms} ms" if res.status == "ONLINE" else ""
        )
        print(
            f"{res.host:<18} {res.port:<7} {res.service:<10} "
            f"{res.status:<10} {time_str:<14} {res.notes}",
        )

    total = len(results)
    online_cnt = sum(1 for r in results if r.status == "ONLINE")
    offline_cnt = total - online_cnt

    print("\n=== Scan Statistics ===")
    print(f"Total Scanned : {total}")
    pct_on = (online_cnt / total * 100) if total else 0
    pct_off = (offline_cnt / total * 100) if total else 0
    print(f"Online        : {online_cnt} ({pct_on:.1f}%)")
    print(f"Offline       : {offline_cnt} ({pct_off:.1f}%)")

    if out_csv:
        out_path = Path(out_csv)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "Target Host",
                    "Port",
                    "Service",
                    "Status",
                    "Response Time (ms)",
                    "Notes",
                ],
            )
            for r in results:
                writer.writerow(
                    [
                        r.host,
                        r.port,
                        r.service,
                        r.status,
                        r.response_time_ms,
                        r.notes,
                    ],
                )
        logging.info(f"\nDetailed scan report saved to {out_csv}")
