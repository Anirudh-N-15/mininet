"""Unit tests for step 3's detectors.   python3 -m unittest egl.test_detectors"""

import random
import unittest

from egl.detectors import EWMA, HST, Static, make


def normal(rng):
    syn = max(0.0, rng.gauss(6, 0.6))
    return {"syn": syn, "srv_tx": syn * 6.5}


def warm(det, n=60, seed=1):
    rng = random.Random(seed)
    for _ in range(n):
        v = det.observe(normal(rng))
        assert not v.alarm
    return rng


class CommonTest(unittest.TestCase):
    def test_make_builds_all_three(self):
        self.assertEqual([d.name for d in make("static, ewma,hst")],
                         ["static", "ewma", "hst"])

    def test_no_alarms_while_warming(self):
        for det in make("static,ewma,hst"):
            v = det.observe({"syn": 1000.0, "srv_tx": 1000.0})
            self.assertTrue(v.warming)
            self.assertFalse(v.alarm)

    def test_every_detector_catches_abrupt_10x(self):
        for det in make("static,ewma,hst"):
            warm(det)
            self.assertTrue(det.observe({"syn": 60.0, "srv_tx": 390.0}).alarm, det.name)

    def test_quiet_on_normal_traffic(self):
        for det in make("static,ewma,hst"):
            rng = warm(det)
            alarms = sum(det.observe(normal(rng)).alarm for _ in range(200))
            self.assertEqual(alarms, 0, det.name)


class LearningRuleTest(unittest.TestCase):
    def test_static_never_learns_after_warmup(self):
        det = Static()
        warm(det)
        self.assertFalse(det.observe({"syn": 6.0}).learned)

    def test_ewma_does_not_learn_alarm_windows(self):
        det = EWMA()
        warm(det)
        mu = det.mu
        v = det.observe({"syn": 600.0})
        self.assertTrue(v.alarm and not v.learned)
        self.assertEqual(det.mu, mu)

    def test_allow_learning_false_freezes_ewma(self):
        """The step-4 hook: a closed gate means no learning, even when quiet."""
        det = EWMA()
        rng = warm(det)
        mu = det.mu
        v = det.observe(normal(rng), allow_learning=False)
        self.assertFalse(v.learned)
        self.assertEqual(det.mu, mu)

    def test_allow_learning_false_freezes_hst(self):
        det = HST()
        rng = warm(det)
        seen = det._seen
        det.observe(normal(rng), allow_learning=False)
        self.assertEqual(det._seen, seen)


class FrogBoilingTest(unittest.TestCase):
    """The step-2/3 finding in miniature: a smooth ramp walks EWMA to 10x."""

    def test_ewma_learns_a_slow_ramp(self):
        det, x = EWMA(), 6.0
        warm(det)
        alarms = 0
        while x < 60:
            x *= 1.005
            alarms += det.observe({"syn": x}).alarm
        self.assertEqual(alarms, 0)

    def test_static_alarms_on_the_same_ramp(self):
        det, x = Static(), 6.0
        warm(det)
        alarms = 0
        while x < 60:
            x *= 1.005
            alarms += det.observe({"syn": x}).alarm
        self.assertGreater(alarms, 0)


if __name__ == "__main__":
    unittest.main()


class WarmupFixTest(unittest.TestCase):
    """The first version let a detector learn every warm-up second, even when
    the Learning Gate said the traffic was not real. An attack that started
    during warm-up then became part of "normal". The fix: warm-up seconds
    count only when the gate accepts them."""

    def run_early_attack(self, det, gate_warmup):
        rng = random.Random(4)
        alarms = 0
        for t in range(200):
            attack = t >= 10                      # 10x flood starts in warm-up
            x = normal(rng)
            if attack:
                x = {"syn": x["syn"] + 54, "srv_tx": x["srv_tx"] + 54}
            gate_open = not attack                # completion ~0.1 under attack
            allow = gate_open if (gate_warmup or not det.warming) else True
            alarms += det.observe(x, allow_learning=allow).alarm
        return alarms

    def test_v1_learns_an_attack_that_starts_in_warmup(self):
        self.assertEqual(self.run_early_attack(EWMA(), gate_warmup=False), 0)

    def test_fixed_warmup_catches_it(self):
        self.assertGreater(self.run_early_attack(EWMA(), gate_warmup=True), 0)

    def test_fixed_warmup_catches_it_hst(self):
        self.assertGreater(self.run_early_attack(HST(), gate_warmup=True), 0)

    def test_without_attack_the_fix_changes_nothing(self):
        a, b = EWMA(), EWMA()
        rng1, rng2 = random.Random(9), random.Random(9)
        for _ in range(100):
            va = a.observe(normal(rng1), allow_learning=True)
            vb = b.observe(normal(rng2), allow_learning=True)
            self.assertEqual((va.alarm, va.threshold), (vb.alarm, vb.threshold))
