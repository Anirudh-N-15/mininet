"""Three-switch, ten-host tree for a controlled TCP SYN experiment."""

from mininet.topo import Topo


class SynExperimentTopology(Topo):
    """Two five-host access switches connected to a central switch."""

    def build(self):
        left_switch = self.addSwitch("s1", protocols="OpenFlow13")
        right_switch = self.addSwitch("s2", protocols="OpenFlow13")
        core_switch = self.addSwitch("s3", protocols="OpenFlow13")

        self.addLink(left_switch, core_switch)
        self.addLink(right_switch, core_switch)

        for host_number in range(1, 6):
            host = self.addHost(
                "h%d" % host_number,
                ip="10.0.0.%d/24" % host_number,
            )
            self.addLink(host, left_switch)

        for host_number in range(6, 11):
            host = self.addHost(
                "h%d" % host_number,
                ip="10.0.0.%d/24" % host_number,
            )
            self.addLink(host, right_switch)


topos = {"synexperiment": SynExperimentTopology}