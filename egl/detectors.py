"""Anomaly detectors on the per-second SYN rate x_n. Pure Python.

Step 2 only needs EWMA-z, to replay a measured trace and see whether the ramp
slips past. Step 3 adds the Static and Half-Space-Trees detectors here and
wires them into Ryu.

EWMA-z is the adaptive core of recent SDN detectors (e.g. Zhang et al. 2026):
    mu  <- mu  + beta * (x - mu)
    var <- (1 - beta) * var + beta * (x - mu)^2
    alarm  if  x > mu + kappa * sigma
and, like those detectors, it LEARNS ONLY FROM WINDOWS IT CALLS NORMAL.
That rule is exactly what the frog-boiling ramp exploits: each ramp step is
small enough to be called normal, so it gets learned.
"""

import math


class EWMAZ:
    def __init__(self, beta=0.1, kappa=3.0, warmup=20, poisson_floor=True):
        self.beta, self.kappa, self.warmup = beta, kappa, warmup
        self.poisson_floor = poisson_floor
        self._warm = []
        self.mu = None
        self.var = None

    def sigma(self, dt=1.0):
        s = math.sqrt(max(self.var, 0.0))
        if self.poisson_floor:
            # SYN arrivals are counts: a rate measured over dt seconds has at
            # least Poisson noise sqrt(mu/dt), even if the trace looked flat.
            s = max(s, math.sqrt(max(self.mu, 0.0) / dt))
        return s

    def threshold(self, dt=1.0):
        return self.mu + self.kappa * self.sigma(dt)

    def step(self, x, dt=1.0):
        """Feed one window. Returns True if this window raises an alarm."""
        if self.mu is None:
            self._warm.append(x)
            if len(self._warm) >= self.warmup:
                n = len(self._warm)
                self.mu = sum(self._warm) / n
                self.var = sum((v - self.mu) ** 2 for v in self._warm) / n
            return False
        alarm = x > self.threshold(dt)
        if not alarm:
            d = x - self.mu
            self.mu += self.beta * d
            self.var = (1 - self.beta) * self.var + self.beta * d * d
        return alarm
