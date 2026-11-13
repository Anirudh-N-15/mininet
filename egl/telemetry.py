"""Turn cumulative switch counters into per-window rates and the completion ratio.

Switch counters only ever grow ("total SYNs since the rule was installed").
Every poll we get a Snapshot; this module turns consecutive snapshots into

    x_n  = SYN rate in the last window             (what the detector watches)
    e_n  = server FINs / client SYNs over the last
           `evidence_seconds`                       (what the gate trusts)

Pure Python, no Ryu: tested by test_telemetry.py.
"""

from collections import deque
from dataclasses import dataclass, field

FIELDS = ("syn", "fin", "synack", "srv_tx")


@dataclass
class Snapshot:
    t: float                                    # monotonic seconds
    counts: dict = field(default_factory=dict)  # name -> cumulative packets


@dataclass
class Window:
    t: float
    dt: float
    rates: dict          # name -> packets / s in this window
    deltas: dict         # name -> packets in this window
    completion: object   # float in [0, 1+] or None = not enough evidence
    evidence_syn: int    # SYNs inside the evidence window


def _delta(now, before):
    """Counter difference that survives a counter reset (rule re-installed)."""
    if now is None:
        return 0
    if before is None or now < before:
        return now  # reset: everything counted since the reset is new
    return now - before


class TelemetryWindow:
    def __init__(self, evidence_seconds=5.0, min_syn=3):
        self.evidence_seconds = evidence_seconds
        self.min_syn = min_syn
        self._last = None
        self._history = deque()  # (t, deltas) for the evidence window

    def update(self, snap):
        """Feed one snapshot; returns a Window, or None for the very first one."""
        if self._last is None:
            self._last = snap
            return None
        dt = snap.t - self._last.t
        if dt <= 0:
            return None
        deltas = {k: _delta(snap.counts.get(k), self._last.counts.get(k))
                  for k in FIELDS}
        self._last = snap
        self._history.append((snap.t, deltas))
        while self._history and snap.t - self._history[0][0] >= self.evidence_seconds:
            self._history.popleft()
        syn = sum(d["syn"] for _, d in self._history)
        fin = sum(d["fin"] for _, d in self._history)
        completion = (fin / syn) if syn >= self.min_syn else None
        return Window(
            t=snap.t, dt=dt,
            rates={k: deltas[k] / dt for k in FIELDS},
            deltas=deltas, completion=completion, evidence_syn=syn,
        )
