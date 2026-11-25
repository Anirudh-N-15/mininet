"""Anomaly detectors on the per-second traffic to the server. Pure Python.

All detectors share one interface, so step 4's Learning Gate can wrap any of
them without knowing which one it is:

    det.observe(x, dt=1.0, allow_learning=True) -> Verdict

  * x is a dict of per-second rates from telemetry, e.g. {"syn": 6.0, "srv_tx": 40.2}
  * the detector first SCORES the window (alarm or not), then LEARNS from it
    only if (a) it did not alarm and (b) allow_learning is True.
    (a) is the rule recent SDN detectors use ("update only on normal windows").
    (b) is the hook for step 4: the gate passes allow_learning=False when the
        network cannot vouch for the traffic. In step 3 it is always True.

Detectors never see the completion ratio e_n. Keeping the evidence out of the
detectors is what lets the paper attribute any improvement to the gate alone.

  Static  learns "normal" during warm-up, then never again (your original code)
  EWMA    exponentially weighted mean and variance of the SYN rate
  HST     Half-Space Trees (Tan, Ting & Liu, IJCAI 2011), an online ML
          anomaly detector on (SYN rate, packets to server)
"""

import math
import random
from dataclasses import dataclass


@dataclass
class Verdict:
    alarm: bool
    score: float        # detector-specific: the value compared with the threshold
    threshold: float    # None while warming up
    learned: bool       # did this window update the model?
    warming: bool       # still in warm-up (never alarms then)


MIN_WARM = 5   # fewest clean warm-up seconds a detector will build "normal" from


class Detector:
    name = "base"

    def observe(self, x, dt=1.0, allow_learning=True):
        raise NotImplementedError

    @property
    def warming(self):
        raise NotImplementedError

    def _warm_step(self, value, allow_learning):
        """One warm-up second. Since the warm-up fix, a second the Learning Gate
        rejects is NOT added to the warm-up sample, so an attack that starts
        during warm-up cannot become part of "normal". Returns True when the
        warm-up is complete: `warmup` accepted seconds, or (if the gate keeps
        rejecting, e.g. an attack is running) at least MIN_WARM accepted
        seconds after waiting 3 x warmup seconds in total."""
        self._warm_seen = getattr(self, "_warm_seen", 0) + 1
        if allow_learning:
            self._warm.append(value)
        n = len(self._warm)
        return n >= self.warmup or (self._warm_seen >= 3 * self.warmup and n >= MIN_WARM)


def _poisson_sigma(sigma, mu, dt):
    # SYN rates are counts: a rate measured over dt seconds has at least
    # Poisson noise sqrt(mu / dt), even if the warm-up trace looked flat.
    return max(sigma, math.sqrt(max(mu, 0.0) / dt))


class Static(Detector):
    """Fixed baseline: mean and spread of the warm-up windows, frozen forever."""

    name = "static"

    def __init__(self, kappa=3.0, warmup=20):
        self.kappa, self.warmup = kappa, warmup
        self._warm, self.mu, self.sd = [], None, None

    @property
    def warming(self):
        return self.mu is None

    def observe(self, x, dt=1.0, allow_learning=True):
        v = x["syn"]
        if self.mu is None:
            if self._warm_step(v, allow_learning):
                n = len(self._warm)
                self.mu = sum(self._warm) / n
                self.sd = math.sqrt(sum((w - self.mu) ** 2 for w in self._warm) / n)
            return Verdict(False, v, None, allow_learning, True)
        thr = self.mu + self.kappa * _poisson_sigma(self.sd, self.mu, dt)
        return Verdict(v > thr, v, thr, False, False)


class EWMA(Detector):
    """mu <- mu + beta(x - mu);  var <- (1-beta) var + beta (x - mu)^2;
    alarm if x > mu + kappa * sigma.  The adaptive core of recent SDN detectors."""

    name = "ewma"

    def __init__(self, beta=0.1, kappa=3.0, warmup=20):
        self.beta, self.kappa, self.warmup = beta, kappa, warmup
        self._warm, self.mu, self.var = [], None, None

    def threshold(self, dt=1.0):
        return self.mu + self.kappa * _poisson_sigma(math.sqrt(max(self.var, 0.0)),
                                                     self.mu, dt)

    @property
    def warming(self):
        return self.mu is None

    def observe(self, x, dt=1.0, allow_learning=True):
        v = x["syn"]
        if self.mu is None:
            if self._warm_step(v, allow_learning):
                n = len(self._warm)
                self.mu = sum(self._warm) / n
                self.var = sum((w - self.mu) ** 2 for w in self._warm) / n
            return Verdict(False, v, None, allow_learning, True)
        thr = self.threshold(dt)
        alarm = v > thr
        learn = (not alarm) and allow_learning
        if learn:
            d = v - self.mu
            self.mu += self.beta * d
            self.var = (1 - self.beta) * self.var + self.beta * d * d
        return Verdict(alarm, v, thr, learn, False)


# --------------------------------------------------------------------------
# Half-Space Trees (Tan, Ting & Liu, "Fast Anomaly Detection for Streaming
# Data", IJCAI 2011)
#
# Idea in plain words: cut the feature space in half again and again at random
# (a "half-space tree"). Count how many recent normal points fell in each cell
# (its "mass"). A new point that lands in a cell where hardly any normal points
# were seen is anomalous. Many random trees are averaged so no single unlucky
# cut matters. It learns online in fixed windows: points are counted into a
# "latest" window; when that window is full it becomes the "reference" that
# scores the next points. That window swap is what makes it adaptive.
# --------------------------------------------------------------------------

class _HSTree:
    def __init__(self, depth, lo, hi, rng):
        self.depth = depth
        n_nodes = 2 ** (depth + 1) - 1
        self.dim = [0] * n_nodes
        self.split = [0.0] * n_nodes
        self.r = [0] * n_nodes   # reference mass
        self.l = [0] * n_nodes   # latest mass
        # random workspace around the data range (paper, Algorithm 1)
        mins, maxs = [], []
        for a, b in zip(lo, hi):
            s = rng.uniform(a, b)
            sq = 2 * max(s - a, b - s)
            mins.append(s - sq)
            maxs.append(s + sq)
        self._build(0, 0, mins, maxs, rng)

    def _build(self, node, k, mins, maxs, rng):
        if k == self.depth:
            return
        q = rng.randrange(len(mins))
        mid = (mins[q] + maxs[q]) / 2
        self.dim[node], self.split[node] = q, mid
        left_max, right_min = list(maxs), list(mins)
        left_max[q], right_min[q] = mid, mid
        self._build(2 * node + 1, k + 1, mins, left_max, rng)
        self._build(2 * node + 2, k + 1, right_min, maxs, rng)

    def _child(self, node, p):
        return 2 * node + (1 if p[self.dim[node]] < self.split[node] else 2)

    def score(self, p, size_limit):
        node, k = 0, 0
        while k < self.depth and self.r[node] >= size_limit:
            node, k = self._child(node, p), k + 1
        return self.r[node] * (2 ** k)

    def count(self, p):
        node = 0
        self.l[node] += 1
        for _ in range(self.depth):
            node = self._child(node, p)
            self.l[node] += 1

    def swap(self):
        self.r, self.l = self.l, [0] * len(self.l)


class HST(Detector):
    """Half-Space Trees on (log SYN rate, log packets-to-server rate).

    Higher score = more normal. Alarm if score < threshold, where threshold is
    `factor` x the lowest score seen while calibrating on normal traffic.
    """

    name = "hst"
    FEATURES = ("syn", "srv_tx")

    def __init__(self, n_trees=25, depth=10, window=20, factor=0.5, seed=7,
                 max_rate=10000.0):
        rng = random.Random(seed)
        hi = [math.log1p(max_rate)] * len(self.FEATURES)
        self.trees = [_HSTree(depth, [0.0] * len(hi), hi, rng) for _ in range(n_trees)]
        self.window, self.factor = window, factor
        self.size_limit = max(1, int(0.1 * window))
        self._seen = 0          # points counted into the current latest window
        self._windows_done = 0  # reference windows completed
        self._calib = []
        self.thr = None
        self._warm_seen = 0     # warm-up seconds seen, learned or not
        self._warm_points = []  # clean warm-up points (gate-accepted), for calibration

    def _point(self, x):
        return [math.log1p(max(x.get(f, 0.0), 0.0)) for f in self.FEATURES]

    def _learn(self, p, force_swap=False):
        if p is not None:
            for t in self.trees:
                t.count(p)
            self._seen += 1
        if self._seen >= self.window or (force_swap and self._seen > 0):
            for t in self.trees:
                t.swap()
            self._seen = 0
            self._windows_done += 1

    @property
    def warming(self):
        return self.thr is None

    def observe(self, x, dt=1.0, allow_learning=True):
        p = self._point(x)
        if self.thr is None:
            # Warm-up (fixed): only seconds the gate accepts are learned or used
            # for calibration; if the gate keeps rejecting (an attack is on),
            # finish with what we have after waiting 3 x the normal length.
            self._warm_seen += 1
            waited = self._warm_seen >= 3 * self.window
        if self._windows_done == 0:              # warm-up 1: fill a reference
            if allow_learning:
                self._learn(p)
                self._warm_points.append(p)
            if waited and MIN_WARM <= self._seen < self.window:
                # the gate keeps rejecting (an attack is running): build the
                # reference from the clean seconds we have and calibrate on
                # them straight away -- no clean seconds are coming to wait for
                self._learn(None, force_swap=True)
                self._calib = [sum(t.score(q, self.size_limit) for t in self.trees)
                               / len(self.trees) for q in self._warm_points]
                self.thr = self.factor * min(self._calib)
            return Verdict(False, 0.0, None, allow_learning, True)
        s = sum(t.score(p, self.size_limit) for t in self.trees) / len(self.trees)
        if self.thr is None:                     # warm-up 2: calibrate threshold
            if allow_learning:
                self._calib.append(s)
                self._learn(p)
            if waited and len(self._calib) < MIN_WARM and self._warm_points:
                # the gate kept rejecting (an attack is running): calibrate on
                # the clean seconds already seen in warm-up 1 instead
                self._calib += [sum(t.score(q, self.size_limit) for t in self.trees)
                                / len(self.trees) for q in self._warm_points]
            if len(self._calib) >= self.window or (waited and len(self._calib) >= MIN_WARM):
                self.thr = self.factor * min(self._calib)
            return Verdict(False, s, None, allow_learning, True)
        alarm = s < self.thr
        learn = (not alarm) and allow_learning
        if learn:
            self._learn(p)
        return Verdict(alarm, s, self.thr, learn, False)


def make(names):
    """'static,ewma,hst' -> [Static(), EWMA(), HST()]"""
    table = {"static": Static, "ewma": EWMA, "hst": HST}
    return [table[n.strip()]() for n in names.split(",") if n.strip()]


class EWMAZ(EWMA):
    """Step 2's name and interface for EWMA: step(x_syn, dt) -> alarm."""

    def __init__(self, beta=0.1, kappa=3.0, warmup=20, poisson_floor=True):
        super().__init__(beta, kappa, warmup)

    def step(self, x, dt=1.0):
        return self.observe({"syn": x}, dt).alarm
