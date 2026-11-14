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
