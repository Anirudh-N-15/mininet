#!/usr/bin/env python3
"""Step 5b: turn results/eval/ into the paper's tables and figures.

    python3 -m egl.analyze_eval [--eval results/eval]

Writes results/eval/report/:
  detection.csv / .tex     detection rate, time and x-fold at first alarm (mean +/- 95% CI)
  false_alarms.csv / .tex  flash crowd: runs with a false alarm, per detector
  growth.csv / .tex        ramp speed vs detection, per detector
  completing.csv / .tex    real-IP HTTP bots (the limitation case)
  tau_sweep.csv            OFFLINE replay of recorded traces with other gate thresholds
  drift_sweep.csv          OFFLINE replay with a drift budget
  mitigation.csv / .tex    users OK %, delayed %, half-open peak per policy (mean +/- CI)
  margin.csv / .tex        meter margin vs users and server
  fig_tau.png, fig_mitigation.png
  summary.md               every table in one readable file

The offline sweeps re-run the gate and detectors (pure Python) on the exact
per-second measurements each live run recorded, so every setting is compared
on identical traffic.
"""

import argparse
import csv
import glob
import json
import math
import os
import re
from collections import defaultdict

from egl import detectors
from egl.gate import LearningGate

DETS = ("static", "ewma", "hst", "ewma_egl", "hst_egl", "ewma_egl_legacy", "hst_egl_legacy")
NAMES = {"static": "Static", "ewma": "EWMA", "hst": "HST",
         "ewma_egl": "EWMA+gate", "hst_egl": "HST+gate",
         "ewma_egl_legacy": "EWMA+gate (v1 warm-up)", "hst_egl_legacy": "HST+gate (v1 warm-up)"}
T975 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365,
        8: 2.306, 9: 2.262, 10: 2.228, 15: 2.131, 20: 2.086, 30: 2.042}


# ------------------------------------------------------------- statistics --
def mean_ci(values):
    """(mean, half-width of the 95% t confidence interval, n)."""
    v = [x for x in values if x is not None]
    n = len(v)
    if n == 0:
        return None, None, 0
    m = sum(v) / n
    if n == 1:
        return m, None, 1
    sd = math.sqrt(sum((x - m) ** 2 for x in v) / (n - 1))
    t = T975.get(n - 1) or T975[min(T975, key=lambda k: abs(k - (n - 1)))]
    return m, t * sd / math.sqrt(n), n


def fmt(m, h, digits=1, unit=""):
    if m is None:
        return "--"
    s = ("%." + str(digits) + "f") % m
    return s + unit + ("" if h is None else (" ± %." + str(digits) + "f") % h)


# --------------------------------------------------------------- loading --
def load_json(path):
    with open(path) as fh:
        return json.load(fh)


def load_rows(path):
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))


def detection_runs(stage_dir):
    """[(name, scenario, summary, detector_csv_path)] of a check_step3 stage."""
    out = []
    for path in sorted(glob.glob(os.path.join(stage_dir, "*.json"))):
        base = os.path.basename(path)[:-5]
        name, _, sc = base.rpartition("_")
        csv_path = os.path.join(stage_dir, "%s_%s_detectors.csv" % (name, sc))
        out.append((name, sc, load_json(path), csv_path))
    return out


# ---------------------------------------------------------- live tables --
def detection_table(runs, scenarios=("abrupt", "ramp")):
    rows = []
    for sc in scenarios:
        sel = [s for _, scn, s, _ in runs if scn == sc]
        if not sel:
            continue
        for d in DETS:
            hits = [s["detectors"][d] for s in sel if d in s["detectors"]]
            if not hits:
                continue
            caught = [h for h in hits if h["first_alarm_s"] is not None]
            t = mean_ci([h["first_alarm_s"] for h in caught])
            x = mean_ci([h["x_fold_at_first_alarm"] for h in caught])
            rows.append({"scenario": sc, "detector": NAMES[d],
                         "detected": "%d/%d" % (len(caught), len(hits)),
                         "first_alarm_s": fmt(t[0], t[1]),
                         "x_fold_at_alarm": fmt(x[0], x[1], 2)})
    return rows


def false_alarm_table(runs):
    sel = [s for _, sc, s, _ in runs if sc == "crowd"]
    rows = []
    for d in DETS:
        hits = [s["detectors"][d] for s in sel if d in s["detectors"]]
        if not hits:
            continue
        fa = [h for h in hits if h["alarm_windows"] > 0]
        x = mean_ci([h["x_fold_at_first_alarm"] for h in fa])
        rows.append({"detector": NAMES[d], "runs_with_false_alarm": "%d/%d" % (len(fa), len(hits)),
                     "x_fold_at_false_alarm": fmt(x[0], x[1], 2)})
    return rows


def growth_table(groups):
    """groups: {growth: [summary, ...]}"""
    rows = []
    for g in sorted(groups):
        for d in DETS:
            hits = [s["detectors"][d] for s in groups[g] if d in s["detectors"]]
            if not hits:
                continue
            caught = [h for h in hits if h["first_alarm_s"] is not None]
            x = mean_ci([h["x_fold_at_first_alarm"] for h in caught])
            rows.append({"growth_per_s": "%g%%" % (100 * g), "detector": NAMES[d],
                         "detected": "%d/%d" % (len(caught), len(hits)),
                         "x_fold_at_alarm": fmt(x[0], x[1], 2)})
    return rows


# -------------------------------------------------------- offline replay --
def replay(csv_path, summary, tau=0.7, drift=None, det="ewma"):
    """Re-run one gated detector on a recorded trace.
    Returns (alarms before the event, first alarm x-fold after it or None)."""
    rows = load_rows(csv_path)
    t_users, t_event = summary.get("t_users"), summary.get("t_event")
    if t_event is None:
        return None
    rows = [r for r in rows if float(r["wall_time"]) >= (t_users or 0) + 6]
    base = [float(r["syn_rate"]) for r in rows if float(r["wall_time"]) < t_event]
    bmean = sum(base) / len(base) if base else 1.0
    d = detectors.make(det)[0]
    gate = LearningGate(tau=tau, drift_per_s=drift)
    pre, first = 0, None
    for r in rows:
        x = {"syn": float(r["syn_rate"]), "srv_tx": float(r["srv_tx_rate"])}
        comp = float(r["completion"]) if r["completion"] else None
        v = d.observe(x, allow_learning=gate.decide(x, comp).open)
        if not v.alarm:
            continue
        if float(r["wall_time"]) < t_event:
            pre += 1
        elif first is None and float(r["wall_time"]) <= summary.get("t_end", 1e18):
            first = x["syn"] / bmean
    return pre, first


def sweep(runs_by_kind, values, key, det="ewma"):
    """runs_by_kind: {"ramp": [(summary, csv)], "crowd": [...], "completing": [...]}"""
    rows = []
    for val in values:
        kw = {"tau": 0.7, "drift": None}
        kw[key] = val
        row = {key: "off" if val is None else val}
        for kind, runs in runs_by_kind.items():
            res = [replay(c, s, det=det, **kw) for s, c in runs if os.path.exists(c)]
            res = [r for r in res if r is not None]
            if not res:
                continue
            if kind == "crowd":
                fa = sum(1 for pre, first in res if first is not None)
                row["crowd_false_alarm_runs"] = "%d/%d" % (fa, len(res))
            else:
                caught = [f for _, f in res if f is not None]
                m = mean_ci(caught)
                row["%s_detected" % kind] = "%d/%d" % (len(caught), len(res))
                row["%s_x_fold" % kind] = fmt(m[0], m[1], 2)
            row["warmup_alarms"] = row.get("warmup_alarms", 0) + sum(p for p, _ in res)
        rows.append(row)
    return rows


# ------------------------------------------------------------ mitigation --
def mitigation_table(stage_dir):
    groups = defaultdict(list)
    for path in sorted(glob.glob(os.path.join(stage_dir, "step5_*.json"))):
        s = load_json(path)
        groups[(s["scenario"], s["policy"])].append(s)
    rows = []
    order = {"abrupt": 0, "ramp": 1, "crowd": 2}
    rank = lambda pol: (0 if pol == "none" else 1 if "-meter" in pol else 2, pol)
    for (sc, pol), runs in sorted(groups.items(),
                                  key=lambda kv: (order.get(kv[0][0], 9), rank(kv[0][1]))):
        ok = mean_ci([r["users"]["event"]["success_pct"] for r in runs])
        delayed = mean_ci([r["users"]["event"]["slow_pct"] for r in runs])
        bad = mean_ci([None if r["users"]["event"]["success_pct"] is None else
                       (100 - r["users"]["event"]["success_pct"]) +
                       r["users"]["event"]["success_pct"] * (r["users"]["event"]["slow_pct"] or 0) / 100
                       for r in runs])
        peak = mean_ci([r["half_open"]["event"]["peak"] for r in runs])
        drop = mean_ci([r.get("meter_dropped_share_pct") for r in runs])
        rows.append({"scenario": sc, "policy": pol, "runs": len(runs),
                     "users_ok_pct": fmt(ok[0], ok[1]),
                     "failed_or_delayed_pct": fmt(bad[0], bad[1]),
                     "half_open_peak": fmt(peak[0], peak[1], 0),
                     "meter_dropped_pct": fmt(drop[0], drop[1]),
                     "_bad": bad, "_peak": peak})
    return rows


# --------------------------------------------------------------- output --
def write_csv(path, rows):
    rows = [{k: v for k, v in r.items() if not k.startswith("_")} for r in rows]
    if not rows:
        return
    keys = list(dict.fromkeys(k for r in rows for k in r))
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)


def write_tex(path, rows, caption, label):
    rows = [{k: v for k, v in r.items() if not k.startswith("_")} for r in rows]
    if not rows:
        return
    keys = list(dict.fromkeys(k for r in rows for k in r))
    esc = lambda s: re.sub(r"([%_&#])", r"\\\1", str(s)).replace("±", r"$\pm$")
    lines = [r"\begin{table}[t]", r"\centering\small",
             r"\caption{%s}\label{%s}" % (caption, label),
             r"\begin{tabular}{%s}" % ("l" * len(keys)), r"\toprule",
             " & ".join(esc(k.replace("_", " ")) for k in keys) + r" \\", r"\midrule"]
    lines += [" & ".join(esc(r.get(k, "")) for k in keys) + r" \\" for r in rows]
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")


def md_table(rows):
    rows = [{k: v for k, v in r.items() if not k.startswith("_")} for r in rows]
    if not rows:
        return "_no runs found_\n"
    keys = list(dict.fromkeys(k for r in rows for k in r))
    out = ["| " + " | ".join(keys) + " |", "|" + "---|" * len(keys)]
    out += ["| " + " | ".join(str(r.get(k, "")) for k in keys) + " |" for r in rows]
    return "\n".join(out) + "\n"


def figures(report, tau_rows, mit_rows):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib missing: tables written, figures skipped")
        return
    ink, ink2, grid, surf = "#0b0b0b", "#52514e", "#e4e3df", "#fcfcfb"
    if tau_rows and any("ramp_x_fold" in r for r in tau_rows):
        taus = [r["tau"] for r in tau_rows]
        xf = [float(r["ramp_x_fold"].split(" ")[0]) if r.get("ramp_x_fold", "--") != "--" else None
              for r in tau_rows]
        fa = [int(r["crowd_false_alarm_runs"].split("/")[0]) / max(1, int(r["crowd_false_alarm_runs"].split("/")[1]))
              * 100 if "crowd_false_alarm_runs" in r else None for r in tau_rows]
        fig, axes = plt.subplots(1, 2, figsize=(10, 3.6))
        fig.patch.set_facecolor(surf)
        axes[0].plot(taus, xf, marker="o", color="#2a78d6", lw=2)
        axes[0].set_ylabel("x-fold of normal at first alarm", color=ink2, fontsize=9)
        axes[0].set_title("Slow spoofed ramp: amplification at first alarm", loc="left", fontsize=10.5, color=ink)
        axes[1].plot(taus, fa, marker="o", color="#eb6834", lw=2)
        axes[1].set_ylabel("flash-crowd runs with a false alarm (%)", color=ink2, fontsize=9)
        axes[1].set_ylim(-5, 105)
        axes[1].set_title("Real flash crowd: runs with a false alarm", loc="left", fontsize=10.5, color=ink)
        for ax in axes:
            ax.set_xlabel("Learning Gate threshold tau (completion)", color=ink2, fontsize=9)
            ax.grid(color=grid, lw=0.8)
            ax.set_facecolor(surf)
            for s in ("top", "right"):
                ax.spines[s].set_visible(False)
            ax.tick_params(colors=ink2, labelsize=8.5)
        fig.suptitle("EWMA+gate: choosing tau (offline replay of the recorded runs)",
                     x=0.01, ha="left", fontsize=12, color=ink)
        fig.tight_layout(rect=(0, 0, 1, 0.92))
        fig.savefig(os.path.join(report, "fig_tau.png"), dpi=200, facecolor=surf)
        plt.close(fig)
    if mit_rows:
        colors = {"none": "#a8a7a1", "meter": "#eb6834", "bypass": "#2a78d6"}
        labels = ["%s | %s" % (r["scenario"], r["policy"]) for r in mit_rows]
        fig, axes = plt.subplots(1, 2, figsize=(12, 0.4 * len(mit_rows) + 1.6), sharey=True)
        fig.patch.set_facecolor(surf)
        for ax, key, xl in ((axes[0], "_bad", "user requests failed or delayed (%)"),
                            (axes[1], "_peak", "server half-open peak")):
            for y, r in enumerate(mit_rows):
                m, h, _ = r[key]
                style = "none" if r["policy"] == "none" else r["policy"].split("-")[1]
                ax.barh(y, m or 0, color=colors.get(style, "#888"), height=0.6)
                if h:
                    ax.errorbar(m, y, xerr=h, color=ink, capsize=3, lw=1)
                ax.text((m or 0) + (h or 0), y, "  %.0f" % (m or 0), va="center",
                        fontsize=8, color=ink)
            ax.set_xlabel(xl, color=ink2, fontsize=9)
            ax.grid(axis="x", color=grid, lw=0.8)
            ax.set_facecolor(surf)
            for s in ("top", "right"):
                ax.spines[s].set_visible(False)
            ax.tick_params(colors=ink2, labelsize=8.5)
        axes[0].set_yticks(range(len(labels)))
        axes[0].set_yticklabels(labels, fontsize=8.5)
        axes[0].invert_yaxis()
        fig.suptitle("Mitigation over repeated runs (bars = mean, whiskers = 95% CI)",
                     x=0.01, ha="left", fontsize=12, color=ink)
        from matplotlib.patches import Patch
        fig.legend(handles=[Patch(color=colors["none"], label="no mitigation"),
                            Patch(color=colors["meter"], label="plain SYN meter"),
                            Patch(color=colors["bypass"], label="meter + verified-client bypass")],
                   loc="upper left", bbox_to_anchor=(0.005, 0.95), ncol=3, frameon=False,
                   fontsize=9)
        fig.tight_layout(rect=(0, 0, 1, 0.88))
        fig.savefig(os.path.join(report, "fig_mitigation.png"), dpi=200, facecolor=surf)
        plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--eval", default="results/eval")
    args = ap.parse_args()
    report = os.path.join(args.eval, "report")
    os.makedirs(report, exist_ok=True)
    md = ["# EGL evaluation report\n", "Generated by `python3 -m egl.analyze_eval`. "
          "Values are mean ± 95% CI over repeated live runs.\n"]

    det = detection_runs(os.path.join(args.eval, "detection"))
    t = detection_table(det)
    write_csv(os.path.join(report, "detection.csv"), t)
    write_tex(os.path.join(report, "detection.tex"), t,
              "Detection of an abrupt 10x flood and a slow ramp (+0.5\\%/s) to 10x.", "tab:detection")
    md += ["\n## Detection (live)\n", md_table(t)]
    fa = false_alarm_table(det)
    write_csv(os.path.join(report, "false_alarms.csv"), fa)
    write_tex(os.path.join(report, "false_alarms.tex"), fa,
              "False alarms during a legitimate flash crowd (users x5 in 60 s).", "tab:false-alarms")
    md += ["\n## False alarms on a real flash crowd (live)\n", md_table(fa)]

    groups = defaultdict(list)   # ramp speed -> runs; the speed comes from each result file
    for name, sc, s, _ in det + detection_runs(os.path.join(args.eval, "growth")):
        if sc == "ramp" and s.get("growth_per_s") is not None:
            groups[float(s["growth_per_s"])].append(s)
    g = growth_table(groups)
    write_csv(os.path.join(report, "growth.csv"), g)
    write_tex(os.path.join(report, "growth.tex"), g, "Ramp speed versus detection.", "tab:growth")
    md += ["\n## Ramp speed (live)\n", md_table(g)]

    comp = detection_runs(os.path.join(args.eval, "completing"))
    c = detection_table(comp, scenarios=("ramp",))
    write_csv(os.path.join(report, "completing.csv"), c)
    write_tex(os.path.join(report, "completing.tex"), c,
              "Limitation: bots with real addresses completing HTTP requests (+2\\%/s).",
              "tab:completing")
    md += ["\n## Limitation: completing attacker (live)\n", md_table(c)]

    kinds = {"ramp": [(s, p) for _, sc, s, p in det if sc == "ramp"],
             "crowd": [(s, p) for _, sc, s, p in det if sc == "crowd"],
             "completing": [(s, p) for _, _, s, p in comp]}
    kinds = {k: v for k, v in kinds.items() if v}
    tau_rows = sweep(kinds, (0.3, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95), "tau") if kinds else []
    write_csv(os.path.join(report, "tau_sweep.csv"), tau_rows)
    md += ["\n## Gate threshold tau, EWMA+gate (offline replay)\n", md_table(tau_rows)]
    drift_rows = sweep(kinds, (None, 0.05, 0.02, 0.01, 0.005), "drift") if kinds else []
    write_csv(os.path.join(report, "drift_sweep.csv"), drift_rows)
    md += ["\n## Drift budget, EWMA+gate with tau = 0.7 (offline replay)\n", md_table(drift_rows)]

    early = detection_runs(os.path.join(args.eval, "early"))
    e = detection_table(early, scenarios=("early",))
    write_csv(os.path.join(report, "early.csv"), e)
    write_tex(os.path.join(report, "early.tex"), e,
              "Attack starting inside the warm-up (10 s after the users): first version "
              "of the gate (v1) vs.\\ the fixed warm-up.", "tab:early")
    md += ["\n## Attack during warm-up: v1 vs fixed gate (live)\n", md_table(e)]

    dist = detection_runs(os.path.join(args.eval, "distributed"))
    d = detection_table(dist, scenarios=("abrupt", "ramp"))
    write_csv(os.path.join(report, "distributed.csv"), d)
    write_tex(os.path.join(report, "distributed.tex"), d,
              "Validation: the attack split over three hosts (h1, h11, h12).", "tab:distributed")
    md += ["\n## Distributed attack, 3 hosts (live validation)\n", md_table(d)]
    dmit = mitigation_table(os.path.join(args.eval, "distributed"))
    if dmit:
        write_csv(os.path.join(report, "distributed_mitigation.csv"), dmit)
        md += ["\n## Distributed attack: mitigation (live validation)\n", md_table(dmit)]

    mit = mitigation_table(os.path.join(args.eval, "mitigation"))
    write_csv(os.path.join(report, "mitigation.csv"), mit)
    write_tex(os.path.join(report, "mitigation.tex"), mit,
              "Mitigation: users and server per policy.", "tab:mitigation")
    md += ["\n## Mitigation (live)\n", md_table(mit)]
    mar = mitigation_table(os.path.join(args.eval, "margin"))
    write_csv(os.path.join(report, "margin.csv"), mar)
    write_tex(os.path.join(report, "margin.tex"), mar, "Meter margin (abrupt flood).", "tab:margin")
    md += ["\n## Meter margin (live)\n", md_table(mar)]

    figures(report, tau_rows, mit)
    with open(os.path.join(report, "summary.md"), "w") as fh:
        fh.write("".join(md))
    print("".join(md))
    print("report written to", report)


if __name__ == "__main__":
    main()
