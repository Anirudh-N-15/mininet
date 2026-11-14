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

import time

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController

from egl.topology import SERVER_HOST, SERVER_IP, EGLTopology

GATEWAY_IP = "10.0.0.254"
GATEWAY_HOST = "h5"   # absorbs the server's replies to spoofed sources


def curl_loop(server_ip, period=0.5):
    """A fresh TCP connection every `period` s; http.server closes it (FIN)."""
    return ("while true; do curl -s -o /dev/null --max-time 3 http://%s/; "
            "sleep %s; done" % (server_ip, period))


class Scenario:
    def __init__(self, datapath="kernel", controller_port=6653):
        setLogLevel("warning")
        self.datapath = datapath
        self.net = Mininet(topo=EGLTopology(datapath=datapath), switch=OVSSwitch,
                           controller=RemoteController("c0", ip="127.0.0.1",
                                                       port=controller_port),
                           autoSetMacs=True)
        self.procs = []

    def __enter__(self):
        net = self.net
        net.start()
        if self.datapath == "user":
            for host in net.hosts:
                host.cmd("ethtool -K %s tx off >/dev/null 2>&1" % host.defaultIntf())
        server, gateway = net[SERVER_HOST], net[GATEWAY_HOST]
        server.cmd("sysctl -qw net.ipv4.tcp_syncookies=0")
        server.cmd("ip route add default via %s" % GATEWAY_IP)
        server.cmd("ip neigh replace %s lladdr %s dev %s nud permanent"
                   % (GATEWAY_IP, gateway.MAC(), server.defaultIntf()))
        server.cmd("python3 -m egl.web_server 80 >/dev/null 2>&1 &")
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

    def start_users(self, names, period=0.5):
        for name in names:
            self.procs.append(self.net[name].popen(
                curl_loop(SERVER_IP, period), shell=True))

    def run_bg(self, host, cmd):
        proc = self.net[host].popen(cmd, shell=True)
        self.procs.append(proc)
        return proc
