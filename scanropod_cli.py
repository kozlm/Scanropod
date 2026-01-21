#!/usr/bin/env python3
"""
CLI for Scanropod API.

Examples:

# HTTPS mode with API key (default)
./scanropod_cli.py start \
  --target https://example.com \
  --api-key secret123

# HTTPS mode with self-signed cert
./scanropod_cli.py status <scan_id> \
  --api-key secret123 \
  --insecure

# HTTP mode
./scanropod_cli.py start \
  --target http://example.com \
  --base-url http://localhost:8443
"""

import argparse
import json
import sys
from typing import List, Dict, Any, Optional

import requests


def pretty(data: Any) -> None:
    try:
        print(json.dumps(data, indent=2, ensure_ascii=False))
    except Exception:
        print(data)


def read_targets_file(path: str) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Failed to read targets file '{path}': {e}", file=sys.stderr)
        sys.exit(1)


def build_headers(api_key: Optional[str]) -> Dict[str, str]:
    headers = {}
    if api_key:
        headers["X-API-Key"] = api_key
    return headers


def start(
    base: str,
    targets: List[str],
    targets_file: Optional[str],
    scanners: List[str],
    headers: Dict[str, str],
    verify_tls: bool,
) -> None:
    final_targets = list(targets)
    if targets_file:
        final_targets.extend(read_targets_file(targets_file))

    if not final_targets:
        print("Error: at least one target is required.", file=sys.stderr)
        sys.exit(1)

    body: Dict[str, Any] = {"targets": final_targets}
    if scanners:
        body["scanners"] = scanners

    url = f"{base}/scan/start"

    try:
        resp = requests.post(
            url,
            json=body,
            headers=headers,
            timeout=30,
            verify=verify_tls,
        )
    except requests.RequestException as e:
        print(f"Network error: {e}", file=sys.stderr)
        sys.exit(1)

    if not resp.ok:
        print(f"Request failed: {resp.status_code} {resp.reason}", file=sys.stderr)
        print(resp.text, file=sys.stderr)
        sys.exit(1)

    pretty(resp.json())


def get(
    base: str,
    path: str,
    headers: Dict[str, str],
    verify_tls: bool,
) -> None:
    url = f"{base}/{path}"

    try:
        resp = requests.get(
            url,
            headers=headers,
            timeout=15,
            verify=verify_tls,
        )
    except requests.RequestException as e:
        print(f"Network error: {e}", file=sys.stderr)
        sys.exit(1)

    if not resp.ok:
        print(f"Request failed: {resp.status_code} {resp.reason}", file=sys.stderr)
        print(resp.text, file=sys.stderr)
        sys.exit(1)

    pretty(resp.json())


def post(
    base: str,
    path: str,
    headers: Dict[str, str],
    verify_tls: bool,
) -> None:
    url = f"{base}/{path}"

    try:
        resp = requests.post(
            url,
            headers=headers,
            timeout=15,
            verify=verify_tls,
        )
    except requests.RequestException as e:
        print(f"Network error: {e}", file=sys.stderr)
        sys.exit(1)

    if not resp.ok:
        print(f"Request failed: {resp.status_code} {resp.reason}", file=sys.stderr)
        print(resp.text, file=sys.stderr)
        sys.exit(1)

    pretty(resp.json())


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scanropod_cli",
        description="CLI for Scanropod API",
    )

    p.add_argument(
        "--base-url",
        default="https://localhost:8443",
        help="Base URL of API (default: https://localhost:8443)",
    )
    p.add_argument(
        "--api-key",
        help="API key",
    )
    p.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification (self-signed certs)",
    )

    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("start", help="Start a new scan")
    s.add_argument("--target", action="append", default=[], help="Targets to scan")
    s.add_argument("--targets-file", help="File with targets (one per line)")
    s.add_argument("--scanner", action="append", default=[], help="Scanners to use")

    sub.add_parser("status", help="Get scan status").add_argument("scan_id")
    sub.add_parser("result", help="Get scan result").add_argument("scan_id")
    sub.add_parser("stop", help="Stop running scan").add_argument("scan_id")

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    headers = build_headers(args.api_key)
    verify_tls = not args.insecure

    if args.cmd == "start":
        start(
            base,
            targets=args.target,
            targets_file=args.targets_file,
            scanners=args.scanner,
            headers=headers,
            verify_tls=verify_tls,
        )
    elif args.cmd == "status":
        get(base, f"scan/status/{args.scan_id}", headers, verify_tls)
    elif args.cmd == "result":
        get(base, f"scan/result/{args.scan_id}", headers, verify_tls)
    elif args.cmd == "stop":
        post(base, f"scan/stop/{args.scan_id}", headers, verify_tls)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
