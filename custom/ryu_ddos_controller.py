#!/usr/bin/env python3

import json
import os
from datetime import datetime, timezone

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ether_types
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

from ddos_events import EventMitigationRequest


class RyuDDoSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.blocked_flows = set()
        self.control_path = os.environ.get(
            "DDOS_RUN_CONTROL",
            "/home/anirudh/mininet/results/current_run.json",
        )

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            for attacker_ip, victim_ip in self.blocked_flows:
                self.install_drop_flow(datapath, attacker_ip, victim_ip)
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(getattr(datapath, "id", None), None)

    @set_ev_cls(EventMitigationRequest, MAIN_DISPATCHER)
    def mitigation_request_handler(self, ev):
        flow = (ev.attacker_ip, ev.victim_ip)
        if flow in self.blocked_flows:
            return
        self.blocked_flows.add(flow)
        for datapath in list(self.datapaths.values()):
            self.install_drop_flow(datapath, ev.attacker_ip, ev.victim_ip)
        self.logger.warning(
            "Selective mitigation installed: %s -> %s",
            ev.attacker_ip,
            ev.victim_ip,
        )
        self._record_mitigation_time()

    def _record_mitigation_time(self):
        try:
            with open(self.control_path, encoding="utf-8") as control_file:
                control = json.load(control_file)
            control["mitigation_install_time"] = datetime.now(
                timezone.utc
            ).isoformat()
            with open(self.control_path, "w", encoding="utf-8") as control_file:
                json.dump(control, control_file, indent=2)
                control_file.write("\n")
        except (OSError, json.JSONDecodeError):
            self.logger.debug("Unable to record mitigation time", exc_info=True)

    def install_drop_flow(self, datapath, attacker_ip, victim_ip):
        match = datapath.ofproto_parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=attacker_ip,
            ipv4_dst=victim_ip,
        )
        self.add_flow(datapath, 100, match, [])

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER,
            )
        ]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        instructions = [
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
        ]
        if buffer_id is not None:
            flow_mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=instructions,
            )
        else:
            flow_mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=instructions,
            )
        datapath.send_msg(flow_mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]
        parsed_packet = packet.Packet(msg.data)
        ethernet_frame = parsed_packet.get_protocol(ethernet.ethernet)

        if ethernet_frame is None:
            return
        if ethernet_frame.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        if ethernet_frame.dst.lower().startswith("33:33:"):
            return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][ethernet_frame.src] = in_port
        out_port = self.mac_to_port[dpid].get(
            ethernet_frame.dst,
            ofproto.OFPP_FLOOD,
        )
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port,
                eth_dst=ethernet_frame.dst,
                eth_src=ethernet_frame.src,
            )
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(
                    datapath,
                    10,
                    match,
                    actions,
                    msg.buffer_id,
                )
                return
            self.add_flow(datapath, 10, match, actions)

        data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)