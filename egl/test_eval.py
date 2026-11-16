"""Unit tests for the evaluation analysis.   python3 -m unittest egl.test_eval"""

import csv
import os
import tempfile
import unittest

from egl.analyze_eval import fmt, mean_ci, replay


class StatsTest(unittest.TestCase):
    def test_mean_ci_matches_hand_calculation(self):
        # values 1..5: mean 3, sd 1.5811, t(4) = 2.776 -> 2.776 * 1.5811 / sqrt(5) = 1.963
        m, h, n = mean_ci([1, 2, 3, 4, 5])
        self.assertEqual((m, n), (3, 5))
        self.assertAlmostEqual(h, 1.963, places=3)

    def test_single_value_has_no_interval(self):
        self.assertEqual(mean_ci([7]), (7, None, 1))

    def test_missing_values_are_ignored(self):
        self.assertEqual(mean_ci([None, 4, None])[0], 4)
        self.assertEqual(mean_ci([]), (None, None, 0))

    def test_format(self):
        self.assertEqual(fmt(2.0, 0.25, 2), "2.00 ± 0.25")
        self.assertEqual(fmt(None, None), "--")


class ReplayTest(unittest.TestCase):
    """Replay a synthetic trace: 60 s of users, then a ramp whose SYNs never
    complete. EWMA+gate must catch it; with the gate effectively off
    (tau = 0) it must not."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "t.csv")
        rows, m = [], 1.0
        for i in range(400):
            t = 1000.0 + i
            if i >= 70:
                m = min(m * 1.01, 10)
            syn = 6.0 * m
            rows.append({"wall_time": t, "syn_rate": syn, "srv_tx_rate": 40 * m,
                         "completion": round(1.0 / m, 3)})
        with open(self.path, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
        self.summary = {"t_users": 1000.0, "t_event": 1070.0, "t_end": 1400.0}

    def test_gate_catches_the_ramp(self):
        pre, first = replay(self.path, self.summary, tau=0.7)
        self.assertEqual(pre, 0)
        self.assertIsNotNone(first)
        self.assertLess(first, 4)

    def test_without_the_gate_the_ramp_is_learned(self):
        pre, first = replay(self.path, self.summary, tau=0.0)
        self.assertIsNone(first)


if __name__ == "__main__":
    unittest.main()
