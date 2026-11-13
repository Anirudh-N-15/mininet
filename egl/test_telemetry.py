"""Unit tests for the pure parts of step 1.   python3 -m unittest egl.test_telemetry"""

import unittest
from types import SimpleNamespace

from egl import pipeline
from egl.telemetry import Snapshot, TelemetryWindow


def snap(t, syn=0, fin=0, synack=0, srv_tx=0):
    return Snapshot(t, dict(syn=syn, fin=fin, synack=synack, srv_tx=srv_tx))


class TelemetryTest(unittest.TestCase):
    def test_first_snapshot_gives_no_window(self):
        self.assertIsNone(TelemetryWindow().update(snap(0)))

    def test_rates_are_per_second(self):
        tw = TelemetryWindow()
        tw.update(snap(0, syn=0))
        w = tw.update(snap(2, syn=10, fin=10))
        self.assertEqual(w.rates["syn"], 5.0)
        self.assertEqual(w.deltas["fin"], 10)

    def test_legit_traffic_completes(self):
        tw = TelemetryWindow(evidence_seconds=5, min_syn=3)
        tw.update(snap(0))
        for t in range(1, 6):
            w = tw.update(snap(t, syn=4 * t, fin=4 * t))
        self.assertAlmostEqual(w.completion, 1.0)

    def test_flood_drives_completion_to_zero(self):
        tw = TelemetryWindow(evidence_seconds=5, min_syn=3)
        tw.update(snap(0))
        syn = fin = 0
        for t in range(1, 11):
            syn += 4 + (200 if t > 5 else 0)  # flood starts at t=6
            fin += 4
            w = tw.update(snap(t, syn=syn, fin=fin))
        # last 5 windows: 1020 SYN, 20 FIN
        self.assertAlmostEqual(w.completion, 20 / 1020)

    def test_evidence_window_forgets_old_flood(self):
        tw = TelemetryWindow(evidence_seconds=3, min_syn=3)
        tw.update(snap(0))
        tw.update(snap(1, syn=500))           # flood, then calm
        syn, fin = 500, 0
        for t in range(2, 6):
            syn += 4
            fin += 4
            w = tw.update(snap(t, syn=syn, fin=fin))
        self.assertAlmostEqual(w.completion, 1.0)

    def test_too_few_syn_means_no_evidence(self):
        tw = TelemetryWindow(min_syn=3)
        tw.update(snap(0))
        self.assertIsNone(tw.update(snap(1, syn=2, fin=2)).completion)

    def test_counter_reset_is_not_negative(self):
        tw = TelemetryWindow()
        tw.update(snap(0, syn=1000))
        w = tw.update(snap(1, syn=7))       # rule re-installed -> reset
        self.assertEqual(w.deltas["syn"], 7)


class PipelineTest(unittest.TestCase):
    cfg = SimpleNamespace(server_ip="10.0.0.10", server_tcp_port=80,
                          server_ofport=6)

    def test_rules_are_disjoint_by_direction_or_flags(self):
        rules = {n: f for n, _, _, f in pipeline.telemetry_rules(self.cfg)}
        self.assertEqual(rules["syn"]["ipv4_dst"], "10.0.0.10")
        self.assertNotIn("ipv4_dst", rules["fin"])
        self.assertEqual(rules["fin"]["in_port"], 6)  # pinned to server cable
        # SYN rule must exclude the server's SYN-ACK (ACK bit in mask, not value)
        value, mask = rules["syn"]["tcp_flags"]
        self.assertTrue(mask & pipeline.ACK and not value & pipeline.ACK)

    def test_every_counter_has_a_unique_cookie(self):
        cookies = [c for _, _, c, _ in pipeline.telemetry_rules(self.cfg)]
        self.assertEqual(len(cookies), len(set(cookies)))
        self.assertTrue(all(c in pipeline.COUNTER_NAMES for c in cookies))


if __name__ == "__main__":
    unittest.main()
