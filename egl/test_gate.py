"""Unit tests for step 4's Learning Gate.   python3 -m unittest egl.test_gate"""

import random
import unittest

from egl.detectors import EWMA, HST
from egl.gate import LearningGate


def users(rng, scale=1.0):
    syn = max(0.0, rng.gauss(6 * scale, 0.6 * scale ** 0.5))
    return {"syn": syn, "srv_tx": 6.5 * syn}


class GateDecisionTest(unittest.TestCase):
    def test_opens_on_good_evidence(self):
        g = LearningGate(tau=0.7)
        self.assertTrue(g.decide({"syn": 6}, 0.98).open)

    def test_closes_on_low_completion(self):
        d = LearningGate(tau=0.7).decide({"syn": 60}, 0.1)
        self.assertEqual((d.open, d.reason), (False, "low-completion"))

    def test_no_traffic_is_safe_to_learn(self):
        d = LearningGate().decide({"syn": 0.2}, None)
        self.assertEqual((d.open, d.reason), (True, "no-traffic"))

    def test_anchor_only_counts_trusted_windows(self):
        g = LearningGate(tau=0.7)
        for _ in range(30):
            g.decide({"syn": 6.0}, 1.0)
        for _ in range(30):
            g.decide({"syn": 600.0}, 0.01)   # attack windows: not trusted
        self.assertEqual(g.anchor[0], 6.0)

    def test_drift_budget_refuses_fast_growth_even_with_evidence(self):
        g = LearningGate(tau=0.7, drift_per_s=0.01, anchor_windows=60)
        for _ in range(60):
            g.decide({"syn": 6.0}, 1.0)
        # 30 trusted windows of median 6 allow 6 * 1.01^30 = 8.1
        self.assertTrue(g.decide({"syn": 7.5}, 1.0).open)
        self.assertEqual(g.decide({"syn": 30.0}, 1.0).reason, "too-fast")


class GatedDetectorTest(unittest.TestCase):
    """The paper's claim in miniature, with completion ~ users / total."""

    def run_ramp(self, det, gated, growth=0.005, cap=10.0):
        rng, gate = random.Random(5), LearningGate(tau=0.7)
        for _ in range(60):
            x = users(rng)
            det.observe(x, allow_learning=gate.decide(x, 1.0).open if gated else True)
        m = 1.0
        while m < cap:
            m *= 1 + growth
            x = users(rng)
            attack = (m - 1) * 6
            x = {"syn": x["syn"] + attack, "srv_tx": x["srv_tx"] + attack}
            completion = 6 / (6 + attack)          # spoofed SYNs never finish
            v = det.observe(x, allow_learning=gate.decide(x, completion).open if gated else True)
            if v.alarm:
                return m
        return None

    def run_crowd(self, det, gated, factor=5.0, seconds=60):
        rng, gate = random.Random(6), LearningGate(tau=0.7)
        for _ in range(60):
            x = users(rng)
            det.observe(x, allow_learning=gate.decide(x, 1.0).open if gated else True)
        alarms = 0
        for t in range(seconds + 30):
            x = users(rng, scale=min(factor ** (t / seconds), factor))
            v = det.observe(x, allow_learning=gate.decide(x, 0.98).open if gated else True)
            alarms += v.alarm
        return alarms

    def test_plain_ewma_misses_the_slow_ramp(self):
        self.assertIsNone(self.run_ramp(EWMA(), gated=False))

    def test_gated_ewma_catches_the_slow_ramp_early(self):
        m = self.run_ramp(EWMA(), gated=True)
        self.assertIsNotNone(m)
        self.assertLess(m, 4.0)

    def test_gated_ewma_still_accepts_a_real_crowd(self):
        self.assertEqual(self.run_crowd(EWMA(), gated=True), 0)

    def test_gated_hst_catches_the_slow_ramp(self):
        self.assertIsNotNone(self.run_ramp(HST(), gated=True))


if __name__ == "__main__":
    unittest.main()
