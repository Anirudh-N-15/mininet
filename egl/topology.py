"""Experiment topology (same shape as custom/syn_experiment_topology.py).

    s1 (h1..h5, h11) --- s3 (core, h12) --- s2 (h6..h10)

h1, h11 and h12 are the attackers: the attack is split across three machines
on different switches, so it is a real distributed (DDoS) attack.

Mininet numbers switch ports in the order links are added. s2's first link is to
s3 (port 1), then h6..h10 get ports 2..6, so the server h10 is s2 port 6.
SERVER_DPID / SERVER_OFPORT below must match EGL_SERVER_DPID / _OFPORT.
h11 and h12 are added after every s2 link, so s2's port numbers do not change.
"""

from mininet.topo import Topo

SERVER_HOST, SERVER_IP = "h10", "10.0.0.10"
SERVER_DPID, SERVER_OFPORT = 2, 6
ATTACKERS = ("h1", "h11", "h12")


class EGLTopology(Topo):
    def build(self, datapath="kernel"):
        opts = dict(protocols="OpenFlow13", datapath=datapath)
        s1 = self.addSwitch("s1", dpid="1", **opts)
        s2 = self.addSwitch("s2", dpid="2", **opts)
        s3 = self.addSwitch("s3", dpid="3", **opts)
        self.addLink(s1, s3)
        self.addLink(s2, s3)
        for n in range(1, 6):
            self.addLink(self.addHost("h%d" % n, ip="10.0.0.%d/24" % n), s1)
        for n in range(6, 11):
            self.addLink(self.addHost("h%d" % n, ip="10.0.0.%d/24" % n), s2)
        # extra attackers on two other switches (added last: s2 ports unchanged)
        self.addLink(self.addHost("h11", ip="10.0.0.11/24"), s1)
        self.addLink(self.addHost("h12", ip="10.0.0.12/24"), s3)


topos = {"egl": EGLTopology}
