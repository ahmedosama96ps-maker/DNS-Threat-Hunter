#!/usr/bin/env python3
"""Heuristic DNS hunting over Zeek dns.log (TSV or JSON lines).

This is an analyst triage aid, not malware attribution or a production detector.
Use only approved, locally collected telemetry.
"""
import argparse
import collections
import datetime as dt
import ipaddress
import json
import sys
from pathlib import Path


def parse_logs(path):
    fields = None
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line_number, raw in enumerate(handle, start=1):
            line = raw.strip()
            if not line:
                continue
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#"):
                continue
            try:
                if line.startswith("{"):
                    record = json.loads(line)
                else:
                    if fields is None:
                        raise ValueError("Zeek TSV #fields header not found")
                    values = line.split("\t")
                    record = dict(zip(fields, values))
                if isinstance(record, dict):
                    yield record
            except (ValueError, json.JSONDecodeError) as exc:
                print(f"Warning: skipped malformed line {line_number}: {exc}", file=sys.stderr)


def array(value):
    if isinstance(value, list):
        return value
    if value in (None, "", "-"):
        return []
    return str(value).split(",")


def public_a_records(record):
    found = []
    for address in array(record.get("answers")):
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        if parsed.version == 4:
            found.append(str(parsed))
    return found


def time_bucket(record, seconds):
    try:
        return int(float(record.get("ts", 0)) // seconds)
    except (TypeError, ValueError):
        return 0


def detect(records, window=60, dga_min=10, tunnel_label_min=45, flux_ttl_max=60):
    by_source_window = collections.defaultdict(list)
    by_domain = collections.defaultdict(list)
    alerts = []
    for record in records:
        query = str(record.get("query", "")).lower().rstrip(".")
        if not query or query == "-":
            continue
        source = str(record.get("id.orig_h", "unknown"))
        by_source_window[(source, time_bucket(record, window))].append((query, record))
        by_domain[query].append(record)
        labels = query.split(".")
        if any(len(label) >= tunnel_label_min for label in labels[:-1]):
            alerts.append({
                "type": "long_dns_label", "source": source, "query": query,
                "reason": f"Non-terminal DNS label >= {tunnel_label_min} characters",
            })

    for (source, bucket), entries in by_source_window.items():
        failed = [
            query for query, record in entries
            if str(record.get("rcode_name", "")).upper() == "NXDOMAIN"
            or str(record.get("rcode", "")) == "3"
        ]
        unique_failed = set(failed)
        if len(unique_failed) >= dga_min:
            alerts.append({
                "type": "nxdomain_burst", "source": source,
                "window_start_epoch": bucket * window,
                "unique_failed_queries": len(unique_failed),
                "reason": "Many distinct NXDOMAIN queries in one time window; may also be benign",
            })

    for query, entries in by_domain.items():
        addresses = set()
        low_ttl = False
        for record in entries:
            addresses.update(public_a_records(record))
            for ttl in array(record.get("TTLs")):
                try:
                    low_ttl |= float(ttl) <= flux_ttl_max
                except ValueError:
                    pass
        if len(addresses) >= 3 and low_ttl:
            alerts.append({
                "type": "multi_a_low_ttl", "query": query,
                "unique_ipv4_answers": len(addresses),
                "reason": f"At least 3 IPv4 answers with some TTL <= {flux_ttl_max}s",
            })
    return alerts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dns_log", type=Path, help="Zeek dns.log in TSV or JSON format")
    parser.add_argument("--window", type=int, default=60, help="NXDOMAIN burst window in seconds")
    parser.add_argument("--min-nxdomain", type=int, default=10)
    parser.add_argument("--min-label", type=int, default=45)
    parser.add_argument("--max-flux-ttl", type=int, default=60)
    args = parser.parse_args()
    if args.window < 1 or args.min_nxdomain < 1 or args.min_label < 1 or args.max_flux_ttl < 0:
        parser.error("Thresholds must be positive (TTL may be zero)")
    if not args.dns_log.is_file():
        parser.error(f"File not found: {args.dns_log}")
    alerts = detect(
        parse_logs(args.dns_log), args.window, args.min_nxdomain,
        args.min_label, args.max_flux_ttl,
    )
    print(json.dumps({"alert_count": len(alerts), "alerts": alerts}, indent=2))


if __name__ == "__main__":
    main()
