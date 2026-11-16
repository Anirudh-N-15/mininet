"""Unit tests for step 5's pure parts.   python3 -m unittest egl.test_mitigation"""

import os
import tempfile
import unittest
from types import SimpleNamespace

from egl import pipeline, user_metrics as um
from egl.scenario import curl_loop, pool_addresses
from egl.telemetry import Snapshot, TelemetryWindow


class BypassCountingTest(unittest.TestCase):
    """SYNs that skip the meter are counted by bypass rules; telemetry must
    still see them as SYNs, and removing the rules must not cause a spike."""

    def test_bypassed_syns_still_count(self):
        tw = TelemetryWindow()
        tw.update(Snapshot(0, dict(syn=100, fin=0, synack=0, srv_tx=0)))
        w = tw.update(Snapshot(1, dict(syn=150, fin=0, synack=0, srv_tx=0, bypass=10)))
        self.assertEqual(w.deltas["syn"], 60)

    def test_removing_bypass_rules_is_not_a_spike(self):
        tw = TelemetryWindow()
        tw.update(Snapshot(0, dict(syn=100, fin=0, synack=0, srv_tx=0, bypass=500)))
        w = tw.update(Snapshot(1, dict(syn=106, fin=0, synack=0, srv_tx=0)))  # rules gone
        self.assertEqual(w.deltas["syn"], 6)


class MatchTest(unittest.TestCase):
    cfg = SimpleNamespace(server_ip="10.0.0.10", server_tcp_port=80, server_ofport=6)

    def test_bypass_rule_is_the_syn_rule_plus_a_source(self):
        syn = pipeline.syn_fields(self.cfg)
        self.assertEqual(syn["tcp_flags"], (pipeline.SYN, pipeline.SYN | pipeline.ACK))
        self.assertEqual(syn["ipv4_dst"], "10.0.0.10")

    def test_fin_evidence_is_pinned_to_the_server_port(self):
        self.assertEqual(pipeline.fin_fields(self.cfg)["in_port"], 6)

    def test_bypass_cookie_is_a_counter(self):
        self.assertEqual(pipeline.COUNTER_NAMES[pipeline.COOKIE_BYPASS], "bypass")


class PoolTest(unittest.TestCase):
    def test_pools_are_disjoint_and_inside_the_subnet(self):
        seen = set()
        for host in ("h2", "h3", "h4", "h6", "h7", "h8", "h9"):
            addrs = pool_addresses(host, 30)
            self.assertEqual(len(addrs), 30)
            self.assertFalse(seen & set(addrs))
            seen |= set(addrs)
        last = max(int(a.split(".")[-1]) for a in seen)
        self.assertLess(last, 254)                    # .254 is the gateway
        self.assertNotIn("10.0.0.10", seen)           # the server

    def test_curl_loop_logs_and_picks_a_source(self):
        cmd = curl_loop("10.0.0.10", 0.5, "/tmp/c.log", ["10.0.0.20", "10.0.0.21"])
        self.assertIn("--interface $src", cmd)
        self.assertIn("shuf -n1 -e 10.0.0.20 10.0.0.21", cmd)
        self.assertIn(">> /tmp/c.log", cmd)


class UserMetricsTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        with open(os.path.join(self.dir, "h2_1.log"), "w") as fh:
            fh.write("100.0 200 0.001\n101.0 200 1.003\n102.0 000 0\nbad line\n"
                     "200.0 200 0.002\n")

    def test_success_and_retries(self):
        s = um.request_stats(um.load_requests(self.dir), [(100, 110)])
        self.assertEqual(s["requests"], 3)
        self.assertAlmostEqual(s["success_pct"], 66.7)
        self.assertEqual(s["slow_pct"], 50.0)        # one of two needed a retry

    def test_spans(self):
        s = um.request_stats(um.load_requests(self.dir), [(150, 250)])
        self.assertEqual((s["requests"], s["success_pct"]), (1, 100.0))

    def test_empty_span(self):
        s = um.request_stats([], [(0, 1)])
        self.assertIsNone(s["success_pct"])


if __name__ == "__main__":
    unittest.main()
