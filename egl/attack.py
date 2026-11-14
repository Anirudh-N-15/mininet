"""Attack schedules and packet pacing. Pure Python, no sockets (tested alone).

The attacker knows (roughly) the legitimate SYN rate L0 and wants the TOTAL
SYN rate at the server to be  m(t) * L0, where m is the "amplification":

    abrupt : m(t) = cap                          (jump straight to cap x)
    ramp   : m(t) = min((1 + growth)^t, cap)     (frog-boiling: +growth per s)

so the attack itself sends  (m(t) - 1) * L0  packets per second.

With growth = 0.02 the total reaches 10x after ln(10)/ln(1.02) = 116 s.
That is the "+20 % above the learned baseline" case of the design: an EWMA
with beta = 0.1 lags a 2 %/s ramp by about growth/beta = 20 %.
"""

import math

MODES = ("abrupt", "ramp")


def amplification(mode, t, growth=0.02, cap=10.0):
    """Target total-rate multiplier m(t) at t seconds after attack start."""
    if t < 0:
        return 1.0
    if mode == "abrupt":
        return cap
    if mode == "ramp":
        return min((1.0 + growth) ** t, cap)
    raise ValueError("mode must be one of %s" % (MODES,))


def attack_rate(mode, t, base_rate, growth=0.02, cap=10.0):
    """Packets per second the ATTACKER must send at time t."""
    return (amplification(mode, t, growth, cap) - 1.0) * base_rate


def seconds_to_reach(factor, growth):
    """Ramp time until the total hits `factor` x (analytic)."""
    return math.log(factor) / math.log(1.0 + growth)


class Pacer:
    """Decides how many packets are due, so the cumulative count follows the
    integral of the rate. Fractional packets carry over, so 0.3 pkt/s still
    sends one packet every ~3 s instead of rounding to zero."""

    def __init__(self, rate_fn):
        self.rate_fn = rate_fn   # t -> packets/s
        self.owed = 0.0          # packets planned but not yet sent
        self.last_t = None

    def due(self, t):
        if self.last_t is None:
            self.last_t = t
            return 0
        dt = max(0.0, t - self.last_t)
        # trapezoid over the step: accurate even while the rate is changing
        self.owed += 0.5 * (self.rate_fn(self.last_t) + self.rate_fn(t)) * dt
        self.last_t = t
        n = int(self.owed + 1e-9)   # 0.3 added 100x is 29.999..., still 30 packets
        self.owed -= n
        return n
