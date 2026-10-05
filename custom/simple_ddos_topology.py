"""Three-switch, four-host tree topology for DDoS monitoring experiments."""

from mininet.topo import Topo


class SimpleDDoSTopology(Topo):
    """Two access switches connected through one central switch."""

    def build(self):
        access_left = self.addSwitch("s1", protocols="OpenFlow13")
        access_right = self.addSwitch("s2", protocols="OpenFlow13")
        core = self.addSwitch("s3", protocols="OpenFlow13")

        self.addLink(access_left, core)
        self.addLink(access_right, core)

        for host_number in (1, 2):
            host = self.addHost(
                "h%d" % host_number,
                ip="10.0.0.%d/24" % host_number,
            )
            self.addLink(host, access_left)

        for host_number in (3, 4):
            host = self.addHost(
                "h%d" % host_number,
                ip="10.0.0.%d/24" % host_number,
            )
            self.addLink(host, access_right)


topos = {"simpleddos": SimpleDDoSTopology}