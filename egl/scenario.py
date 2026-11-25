"""Shared Mininet setup for every EGL experiment (steps 1, 2, 3, ...).

    with Scenario(datapath="kernel") as sc:
        sc.start_users(("h2", "h3", "h6"))
        ...

What it sets up, and why:
  * topology s1(h1..h5) -- s3 -- s2(h6..h10), RemoteController on 6653
  * userspace datapath only: TCP checksum offload off on every host
    (otherwise OVS-netdev + veth drops every TCP packet; ping still works)
  * the server h10: SYN cookies off (so a SYN flood really fills the queue)
    and egl.web_server on port 80 (http.server with a realistic 511 backlog)
  * an "Internet gateway": h10's default route points at 10.0.0.254, a
    made-up address pinned to h5's MAC. Replies to spoofed addresses (SYN-ACKs)
    therefore leave the server like in a real network and are dropped by h5.
    Without a route the kernel cannot even try to answer, so a spoofed SYN
    would never occupy the server's half-open queue, which is unrealistic.
"""

import math
import os
import threading
import time

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController

from egl.topology import ATTACKERS, SERVER_HOST, SERVER_IP, EGLTopology

GATEWAY_IP = "10.0.0.254"
GATEWAY_HOST = "h5"   # absorbs the server's replies to spoofed sources
CROWD_HOSTS = ("h2", "h3", "h4", "h6", "h7", "h8", "h9")  # never h1/h5/h10


def bot_addresses(host, size=8):
    """Real (non-spoofed) bot addresses for the completing attacker, 8 per
    attacker host: h1 10.0.0.230-237, h11 .238-245, h12 .246-253."""
    i = ATTACKERS.index(host)
    return ["10.0.0.%d" % (230 + 8 * i + k) for k in range(min(size, 8))]


def pool_addresses(host, size):
    """Extra client addresses for `host`: 10.0.0.20-49 for h2, 50-79 for h3, ...
    (all inside 10.0.0.0/24, so the server reaches them without a router)."""
    i = CROWD_HOSTS.index(host)
    return ["10.0.0.%d" % (20 + 30 * i + k) for k in range(min(size, 30))]


def curl_loop(server_ip, period=0.5, log=None, sources=None):
    """A fresh TCP connection every `period` s; the server closes it (FIN).

    log:     append "<start epoch> <http code> <connect seconds>" per request
             (code 000 = failed; connect-timeout 3 s, i.e. one SYN retry)
    sources: list of this host's addresses; each request picks one at random,
             so a user population is many distinct client IPs
    """
    pick = ("src=$(shuf -n1 -e %s); " % " ".join(sources)) if sources else ""
    iface = "--interface $src " if sources else ""
    if log is None:
        return ("while true; do %scurl -s -o /dev/null %s--max-time 3 http://%s/; "
                "sleep %s; done" % (pick, iface, server_ip, period))
    return ("while true; do %ss=$(date +%%s.%%N); "
            "r=$(curl -s -o /dev/null -w '%%{http_code} %%{time_connect}' %s"
            "--connect-timeout 3 --max-time 4 http://%s/); "
            'echo "$s ${r:-000 0}" >> %s; sleep %s; done'
            % (pick, iface, server_ip, log, period))


def half_open_loop(log):
    """Once a second: half-open (SYN-RECV) connections on the server's port 80."""
    return ('while true; do echo "$(date +%%s.%%N) '
            '$(ss -tn state syn-recv sport = :80 | tail -n +2 | wc -l)" >> %s; '
            'sleep 1; done' % log)


class Scenario:
    def __init__(self, datapath="kernel", controller_port=6653, backlog=511,
                 new_visitors=False, pool=0, log_dir=None, bots=0):
        """backlog: the server's connection queue (listen backlog and
        tcp_max_syn_backlog). new_visitors: Linux keeps admitting clients it
        recently completed connections with even when its queue is 3/4 full;
        True turns that memory off, so every client is a first-time visitor."""
        setLogLevel("warning")
        self.pool, self.log_dir = pool, log_dir   # step 5: client IP pools, request logs
        self.bots = bots                          # 5b: real bot addresses on h1
        self.datapath = datapath
        self.backlog, self.new_visitors = backlog, new_visitors
        self.net = Mininet(topo=EGLTopology(datapath=datapath), switch=OVSSwitch,
                           controller=RemoteController("c0", ip="127.0.0.1",
                                                       port=controller_port),
                           autoSetMacs=True)
        self.procs = []
        self._loops = {}   # host -> number of user loops started on it

    def __enter__(self):
        net = self.net
        net.start()
        if self.datapath == "user":
            for host in net.hosts:
                host.cmd("ethtool -K %s tx off >/dev/null 2>&1" % host.defaultIntf())
        server, gateway = net[SERVER_HOST], net[GATEWAY_HOST]
        server.cmd("sysctl -qw net.ipv4.tcp_syncookies=0")
        server.cmd("sysctl -qw net.ipv4.tcp_max_syn_backlog=%d" % self.backlog)
        if self.new_visitors:
            server.cmd("sysctl -qw net.ipv4.tcp_no_metrics_save=1")
            server.cmd("ip tcp_metrics flush all")
        server.cmd("ip route add default via %s" % GATEWAY_IP)
        server.cmd("ip neigh replace %s lladdr %s dev %s nud permanent"
                   % (GATEWAY_IP, gateway.MAC(), server.defaultIntf()))
        server.cmd("python3 -m egl.web_server 80 %d >/dev/null 2>&1 &" % self.backlog)
        if self.bots:
            for name in ATTACKERS:
                bot = net[name]
                for addr in bot_addresses(name, self.bots):
                    bot.cmd("ip addr add %s/24 dev %s" % (addr, bot.defaultIntf()))
        if self.pool:
            for name in CROWD_HOSTS:
                host = net[name]
                for addr in pool_addresses(name, self.pool):
                    host.cmd("ip addr add %s/24 dev %s" % (addr, host.defaultIntf()))
        time.sleep(2)
        net.pingAll(timeout=1)   # every switch learns every host first
        return self

    def __exit__(self, *exc):
        for proc in self.procs:
            proc.terminate()
        self.net.stop()
        return False

    def host(self, name):
        return self.net[name]

    def _user_cmd(self, name, k, period):
        log = (os.path.join(self.log_dir, "%s_%d.log" % (name, k))
               if self.log_dir else None)
        sources = pool_addresses(name, self.pool) if self.pool else None
        return curl_loop(SERVER_IP, period, log, sources)

    def start_users(self, names, period=0.5):
        if self.log_dir:
            os.makedirs(self.log_dir, exist_ok=True)
        for name in names:
            self._loops[name] = self._loops.get(name, 0) + 1
            self.procs.append(self.net[name].popen(
                self._user_cmd(name, self._loops[name], period), shell=True))

    def start_half_open_sampler(self, log):
        self.procs.append(self.net[SERVER_HOST].popen(half_open_loop(log), shell=True))

    def start_crowd(self, start_users, factor, seconds, period=0.5):
        """A legitimate flash crowd: the number of users grows from
        start_users to start_users*factor exponentially over `seconds`
        (user k joins at t = seconds * ln(k/start_users) / ln(factor)).
        Users are spread over CROWD_HOSTS; each is one more curl loop.
        Returns immediately; the joins happen on a background thread."""
        target = int(round(start_users * factor))
        joins = [seconds * math.log(k / start_users) / math.log(factor)
                 for k in range(start_users + 1, target + 1)]

        def run():
            t0 = time.time()
            for i, at in enumerate(joins):
                time.sleep(max(0.0, t0 + at - time.time()))
                host = CROWD_HOSTS[(start_users + i) % len(CROWD_HOSTS)]
                self.start_users((host,), period)

        threading.Thread(target=run, daemon=True).start()
        return target

    def start_attack(self, mode, base, growth, cap, duration, log, completing=False,
                     hosts=ATTACKERS):
        """Split one attack evenly over `hosts` (a distributed attack).
        Each host sends 1/k of the schedule with its own random seed and its own
        log (the first host logs to `log`, the others to log_<host>.csv).
        completing=True: real bots doing full HTTP requests from their own
        addresses instead of spoofed SYNs. Returns the processes."""
        procs = []
        for i, host in enumerate(hosts):
            tool = ("egl.http_flood --sources %s" % ",".join(bot_addresses(host, self.bots or 8))
                    if completing else "egl.syn_sender")
            path = log if i == 0 else log[:-4] + "_%s.csv" % host
            procs.append(self.run_bg(host, (
                "python3 -m %s --dst %s --mode %s --base %s --growth %s --cap %s "
                "--duration %s --log %s --seed %d"
                % (tool, SERVER_IP, mode, base / len(hosts), growth, cap, duration,
                   path, 1 + i))))
        return procs

    def run_bg(self, host, cmd):
        proc = self.net[host].popen(cmd, shell=True)
        self.procs.append(proc)
        return proc
