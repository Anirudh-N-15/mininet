"""What did real users experience? Pure Python (tested by test_mitigation.py).

Inputs written during a step-5 run:
  client logs   one line per request:  "<start epoch> <http code> <connect s>"
  half-open log one line per second:   "<epoch> <SYN-RECV count on the server>"

A request "succeeds" if it returned HTTP 200 within the 4 s limit. Its connect
time shows retries: about 1 s means the first SYN was lost and the retry got
through (Linux retries a SYN after 1 s, then 2 s more).
"""

import glob
import os


def percentile(values, q):
    if not values:
        return None
    s = sorted(values)
    pos = (len(s) - 1) * q / 100.0
    lo = int(pos)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (pos - lo)


def load_requests(log_dir):
    rows = []
    for path in sorted(glob.glob(os.path.join(log_dir, "*.log"))):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) != 3:
                    continue
                try:
                    rows.append((float(parts[0]), parts[1], float(parts[2])))
                except ValueError:
                    continue
    return rows


def load_half_open(path):
    rows = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) == 2:
                    try:
                        rows.append((float(parts[0]), int(parts[1])))
                    except ValueError:
                        pass
    except OSError:
        pass
    return rows


def in_spans(t, spans):
    return any(a <= t < b for a, b in spans)


def request_stats(rows, spans):
    """Users' experience for requests that STARTED inside any (start, end) span."""
    sel = [r for r in rows if in_spans(r[0], spans)]
    ok = [r for r in sel if r[1] == "200"]
    conn = [r[2] for r in ok]
    return {
        "requests": len(sel),
        "success_pct": None if not sel else round(100.0 * len(ok) / len(sel), 1),
        "connect_p50_s": None if not conn else round(percentile(conn, 50), 3),
        "connect_p95_s": None if not conn else round(percentile(conn, 95), 3),
        "slow_pct": None if not ok else round(
            100.0 * sum(1 for c in conn if c >= 0.9) / len(ok), 1),
    }


def half_open_stats(rows, spans):
    sel = [v for t, v in rows if in_spans(t, spans)]
    return {"peak": max(sel) if sel else None,
            "mean": None if not sel else round(sum(sel) / len(sel), 1)}
