#!/usr/bin/env python3

from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController

from ddos_topology import DDoSTopology


CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 6633


def run():
    setLogLevel("info")
    controller = RemoteController(
        "c0",
        ip=CONTROLLER_IP,
        port=CONTROLLER_PORT,
    )
    net = Mininet(
        topo=DDoSTopology(),
        controller=controller,
        switch=OVSKernelSwitch,
    )

    try:
        info("*** Starting DDoS topology\n")
        net.start()
        info("*** Running Mininet CLI\n")
        CLI(net)
    finally:
        info("*** Stopping DDoS topology\n")
        net.stop()


if __name__ == "__main__":
    run()