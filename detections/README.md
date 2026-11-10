# Reproducible heuristic DNS hunting

This repository documents a VMware-based lab, with Wireshark and Zeek evidence. A small **standard-library-only Python** triage script has now been added at `detections/dns_hunter.py`. This addition does not retroactively claim these alerts were used during the original investigation.

## Run against your own Zeek logs

From the repository root:

```bash
python3 detections/dns_hunter.py /path/to/dns.log
python3 -m unittest discover -s detections/tests -v
```

The script accepts Zeek TSV logs with `#fields` headers or Zeek JSON lines. It prints JSON alerts. No live attack traffic or external services are required.

## Detection heuristics and limitations

| Signal | Default | Why it matters | Common false positives |
|---|---|---|---|
| NXDOMAIN burst | 10 distinct failed queries from one source within 60 seconds | Potential DGA-like behavior | Search suffix misconfiguration, service discovery, broken applications |
| Long non-terminal DNS label | 45+ characters | Potential encoded DNS payload | Legitimate verification tokens, CDN/analytics labels |
| Multiple IPv4 records with low TTL | 3+ addresses, some TTL <= 60 seconds | Potential fast-flux-like infrastructure | CDNs, load balancers, normal DNS failover |

**Important:** The script does not calculate entropy, prove exfiltration, verify domain ownership, correlate domains to threat intelligence, or prove malicious fast flux. Alerts are triage leads only. Zeek `TTLs` may be missing; in that case a fast-flux-like alert cannot fire based on low TTL. Distinct NXDOMAIN queries across fixed windows may be split at window boundaries. Analysts should corroborate with packet captures, domain history, application activity and broader context.

The script deliberately excludes automatic blocking or public-IP attribution. The tests use synthetic reserved domains and documentation-range IPs.
