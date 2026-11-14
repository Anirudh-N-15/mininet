"""Unit tests for step 2 (no network, no root).   python3 -m unittest egl.test_attack"""

import random
import socket
import struct
import unittest

from egl.attack import Pacer, amplification, attack_rate, seconds_to_reach
from egl.detectors import EWMAZ
from egl.syn_sender import checksum, random_public_ip, syn_packet


class ScheduleTest(unittest.TestCase):
    def test_ramp_grows_geometrically_then_caps(self):
        self.assertEqual(amplification("ramp", 0), 1.0)
        self.assertAlmostEqual(amplification("ramp", 10, growth=0.02), 1.02 ** 10)
        self.assertEqual(amplification("ramp", 1000, growth=0.02, cap=10), 10)

    def test_abrupt_jumps_immediately(self):
        self.assertEqual(amplification("abrupt", 0.0, cap=10), 10)
        self.assertEqual(amplification("abrupt", -1), 1.0)

    def test_attack_rate_excludes_the_legit_share(self):
        self.assertAlmostEqual(attack_rate("abrupt", 5, base_rate=6, cap=10), 54)

    def test_time_to_10x_matches_design_doc(self):
        self.assertAlmostEqual(seconds_to_reach(10, 0.02), 116.28, places=1)


class PacerTest(unittest.TestCase):
    def test_constant_rate_over_ten_seconds(self):
        p, sent = Pacer(lambda t: 50.0), 0
        for i in range(10001):          # 1 ms steps for 10 s
            sent += p.due(i / 1000)
        self.assertEqual(sent, 500)

    def test_fractional_rates_are_not_lost(self):
        p, sent = Pacer(lambda t: 0.3), 0
        for i in range(101):
            sent += p.due(float(i))     # 100 s at 0.3 pkt/s
        self.assertEqual(sent, 30)

    def test_ramp_integral(self):
        rate = lambda t: attack_rate("ramp", t, 6, 0.02, 10)
        p, sent = Pacer(rate), 0
        for i in range(60001):          # 60 s, 1 ms steps
            sent += p.due(i / 1000)
        expected = sum(rate(i / 1000 + 0.0005) for i in range(60000)) / 1000
        self.assertAlmostEqual(sent, expected, delta=1)


class PacketTest(unittest.TestCase):
    def test_checksums_verify(self):
        pkt = syn_packet("45.1.2.3", "10.0.0.10", 40000, 80, 123456)
        ip, tcp = pkt[:20], pkt[20:]
        self.assertEqual(len(pkt), 40)
        self.assertEqual(checksum(ip), 0)   # a correct header sums to 0
        pseudo = ip[12:20] + struct.pack("!BBH", 0, 6, len(tcp))
        self.assertEqual(checksum(pseudo + tcp), 0)

    def test_is_a_bare_syn_to_port_80(self):
        tcp = syn_packet("45.1.2.3", "10.0.0.10", 40000, 80, 1)[20:]
        sport, dport, _, _, _, flags = struct.unpack("!HHIIBB", tcp[:14])
        self.assertEqual((sport, dport, flags), (40000, 80, 0x02))

    def test_spoofed_sources_avoid_private_ranges(self):
        rng = random.Random(0)
        for _ in range(2000):
            first = int(random_public_ip(rng).split(".")[0])
            self.assertNotIn(first, (10, 127, 172, 192))
            self.assertLessEqual(first, 223)


class EWMATest(unittest.TestCase):
    def warmed(self):
        det = EWMAZ(warmup=20)
        rng = random.Random(3)
        for _ in range(40):
            det.step(6 + rng.gauss(0, 0.6))
        return det

    def test_abrupt_10x_alarms(self):
        self.assertTrue(self.warmed().step(60))

    def test_2_percent_ramp_reaches_10x_silently(self):
        det, x, alarms = self.warmed(), 6.0, 0
        while x < 60:
            x *= 1.02
            alarms += det.step(x)
        self.assertEqual(alarms, 0)

    def test_alarm_windows_are_not_learned(self):
        det = self.warmed()
        mu = det.mu
        det.step(600)
        self.assertEqual(det.mu, mu)


if __name__ == "__main__":
    unittest.main()
