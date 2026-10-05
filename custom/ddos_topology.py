"""Four-switch ring with sixteen hosts for Ryu/Mininet experiments."""

from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.topo import Topo


class DDoSTopology(Topo):
    """Four switches in a ring, with four hosts attached to each switch."""

    def build(self):
        switches = [
            self.addSwitch(
                "s1", protocols="OpenFlow13", failMode="standalone", stp=True
            ),
            self.addSwitch(
                "s2", protocols="OpenFlow13", failMode="standalone", stp=True
            ),
            self.addSwitch(
                "s3", protocols="OpenFlow13", failMode="standalone", stp=True
            ),
            self.addSwitch(
                "s4", protocols="OpenFlow13", failMode="standalone", stp=True
            ),
        ]

        # Keep the switch ring in the order s1-s2-s3-s4-s1.
        for left, right in zip(switches, switches[1:] + switches[:1]):
            self.addLink(left, right)

        for switch_index, switch in enumerate(switches):
            first_host = switch_index * 4 + 1
            for host_number in range(first_host, first_host + 4):
                host = self.addHost(
                    "h%d" % host_number,
                    ip="10.0.0.%d/24" % host_number,
                )
                self.addLink(host, switch)


topos = {"ddos": DDoSTopology}


def run():
    """Run the topology directly against a Ryu controller on localhost."""
    setLogLevel("info")
    controller = RemoteController("c0", ip="127.0.0.1", port=6633)
    net = Mininet(
        topo=DDoSTopology(),
        controller=controller,
        switch=OVSKernelSwitch,
    )

    info("*** Starting network\n")
    net.start()
    info("*** Running CLI\n")
    CLI(net)
    info("*** Stopping network\n")
    net.stop()


if __name__ == "__main__":
    run()