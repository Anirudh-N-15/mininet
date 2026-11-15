"""Step 4: the Learning Gate -- the paper's contribution. Pure Python.

The problem (steps 2-3): an adaptive detector learns every window it calls
normal. A slow attack is designed to look normal, so it gets learned.

The fix: decide what a detector may learn from EVIDENCE, not from how normal
the traffic looks. The evidence is the completion ratio from step 1,

    e_n = server FINs / client SYNs  (last 5 s)

Real users -- even a sudden crowd of them -- finish their connections, so
e_n stays near 1. Spoofed or half-open SYNs never reach a server FIN, so every
attack packet pulls e_n down: with the attack at m x the users' rate, e_n is
about 1/m. The gate opens only when e_n >= tau.

    gate.decide(rates, completion) -> GateDecision(open, reason)
    detector.observe(rates, dt, allow_learning=decision.open)

The gate never raises alarms and never touches the detector's alarm rule. It
only decides whether the detector may update its idea of "normal". So it
fixes poisoning (missed slow attacks) but cannot fix a detector that alarms on
any growth (false alarms on real crowds) -- that is the detector's own rule.

Two optional parts, used in the ablation study (step 5):
  * drift budget: even with good evidence, refuse to learn traffic that grew
    faster than `drift_per_s` compared with the trusted traffic of the last
    `anchor_windows` windows. Bounds an attacker who completes real
    handshakes (and so passes the evidence test). Off by default.
  * anchor: median and MAD of the SYN rate over windows the gate approved,
    i.e. a "clean" baseline the attacker could not poison. Step 5's
    mitigator rate-limits SYNs to it.
"""

from collections import deque
from dataclasses import dataclass


@dataclass
class GateDecision:
    open: bool
    reason: str   # "evidence" | "low-completion" | "too-fast" | "no-traffic"


def _median(values):
    s = sorted(values)
    n = len(s)
    if n == 0:
        return None
    return s[n // 2] if n % 2 else 0.5 * (s[n // 2 - 1] + s[n // 2])


class LearningGate:
    def __init__(self, tau=0.7, drift_per_s=None, anchor_windows=120):
        self.tau = tau
        self.drift_per_s = drift_per_s
        self._approved = deque(maxlen=anchor_windows)  # SYN rates the gate trusted

    def decide(self, rates, completion):
        x = rates["syn"]
        if completion is None:
            # fewer than a handful of SYNs in the evidence window: there is
            # almost no traffic, so there is nothing to poison the model with
            decision = GateDecision(True, "no-traffic")
        elif completion < self.tau:
            decision = GateDecision(False, "low-completion")
        elif self.drift_per_s is not None and len(self._approved) >= 10:
            # the median of the trusted windows lags ~len/2 windows behind,
            # so allow (1 + drift)^(len/2) of growth over it
            ceiling = _median(self._approved) * (1 + self.drift_per_s) ** (len(self._approved) / 2)
            decision = (GateDecision(True, "evidence") if x <= ceiling
                        else GateDecision(False, "too-fast"))
        else:
            decision = GateDecision(True, "evidence")
        if decision.open:
            self._approved.append(x)
        return decision

    @property
    def anchor(self):
        """(median, MAD) of the SYN rate over approved windows, or (None, None)."""
        med = _median(self._approved)
        if med is None:
            return None, None
        return med, _median([abs(v - med) for v in self._approved])
