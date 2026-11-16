"""Step 1 of EGL: two-table pipeline + counter telemetry.

    ryu-manager egl/egl_controller.py

What it does
  * every switch:   table 0 catch-all "goto table 1"; table 1 MAC learning
  * server's switch (EGL_SERVER_DPID): also the counting rules from pipeline.py
  * every EGL_POLL_SECONDS: one flow-stats request (table 0) + one port-stats
    request (server port) -> TelemetryWindow -> CSV row + EventTelemetry

Later steps (detector, learning gate, mitigator) are separate Ryu apps that
just do  @set_ev_cls(EventTelemetry)  -- no code in this file changes.
"""

import csv
import os
import time

from ryu.base import app_manager
from ryu.controller import event, ofp_event
from ryu.controller.handler import (CONFIG_DISPATCHER, DEAD_DISPATCHER,
                                    MAIN_DISPATCHER, set_ev_cls)
from ryu.lib import hub
from ryu.lib.packet import arp, ether_types, ethernet, ipv4, packet
from ryu.ofproto import ofproto_v1_3

from egl import pipeline
from egl.config import EGLConfig
from egl.telemetry import FIELDS, Snapshot, TelemetryWindow


class EventTelemetry(event.EventBase):
    """One measurement window. `window` is an egl.telemetry.Window."""

    def __init__(self, window, wall=None):
        super().__init__()
        self.window = window
        self.wall = wall   # wall-clock time of the poll (epoch seconds)


class EGLController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _EVENTS = [EventTelemetry]  # lets other apps subscribe with set_ev_cls

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cfg = EGLConfig.from_env()
        self.mac_to_port = {}       # dpid -> {mac: port}
        self.server_dp = None       # datapath of the server's edge switch
        self.window = TelemetryWindow(self.cfg.evidence_seconds,
                                      self.cfg.min_syn_for_evidence)
        self._pending = {}          # counters of the poll in progress
        self._server_seen_at = None
        self._csv = self._open_csv(self.cfg.telemetry_csv)
        self.logger.info("EGL config: %s", self.cfg)
        hub.spawn(self._poll_loop)

    # ------------------------------------------------------------- pipeline --
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        # clean slate: a reused switch may still hold old rules
        dp.send_msg(parser.OFPFlowMod(dp, command=ofp.OFPFC_DELETE,
                                      table_id=ofp.OFPTT_ALL,
                                      out_port=ofp.OFPP_ANY,
                                      out_group=ofp.OFPG_ANY))
        goto_fwd = [parser.OFPInstructionGotoTable(pipeline.FORWARD_TABLE)]
        # table 0 catch-all: not a telemetry packet -> just forward
        self._add(dp, pipeline.TELEMETRY_TABLE, 0, parser.OFPMatch(), goto_fwd,
                  cookie=pipeline.COOKIE_DEFAULT)
        # table 1 miss: unknown destination -> ask the controller
        to_ctrl = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
            parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)])]
        self._add(dp, pipeline.FORWARD_TABLE, 0, parser.OFPMatch(), to_ctrl)

        if dp.id == self.cfg.server_dpid:
            for name, prio, cookie, fields in pipeline.telemetry_rules(self.cfg):
                inst = goto_fwd
                if name == "fin" and self.cfg.verify_clients:
                    # step 5: also send the first 128 bytes of every server FIN
                    # to Ryu. Its destination is a client that really finished
                    # a connection; the mitigator trusts those clients.
                    inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, [
                        parser.OFPActionOutput(ofp.OFPP_CONTROLLER, 128)])] + goto_fwd
                self._add(dp, pipeline.TELEMETRY_TABLE, prio,
                          parser.OFPMatch(**fields), inst, cookie=cookie)
                self.logger.info("dpid %d: counting rule '%s' installed", dp.id, name)
            self.server_dp = dp

    @set_ev_cls(ofp_event.EventOFPStateChange, DEAD_DISPATCHER)
    def _switch_gone(self, ev):
        if self.server_dp is not None and ev.datapath.id == self.server_dp.id:
            self.server_dp = None

    def _add(self, dp, table, prio, match, inst, cookie=0, idle=0):
        parser = dp.ofproto_parser
        dp.send_msg(parser.OFPFlowMod(dp, table_id=table, priority=prio,
                                      match=match, instructions=inst,
                                      cookie=cookie, idle_timeout=idle))

    # ------------------------------------------- table 1: learning switch --
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        if msg.cookie == pipeline.COOKIE_FIN:
            return  # a FIN copy for the mitigator; the switch already forwarded it
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        self._check_server_location(dp.id, in_port, pkt)

        table = self.mac_to_port.setdefault(dp.id, {})
        table[eth.src] = in_port
        out_port = table.get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofp.OFPP_FLOOD:
            # match on (in_port, dst): a spoofed-IP flood from one host is
            # still ONE rule here, because its MAC never changes
            self._add(dp, pipeline.FORWARD_TABLE, 10,
                      parser.OFPMatch(in_port=in_port, eth_dst=eth.dst),
                      [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)],
                      idle=60)
        dp.send_msg(parser.OFPPacketOut(dp, buffer_id=ofp.OFP_NO_BUFFER,
                                        in_port=in_port, actions=actions,
                                        data=msg.data))

    def _check_server_location(self, dpid, in_port, pkt):
        """Warn once if the configured server port looks wrong.

        The FIN rule is pinned to (EGL_SERVER_DPID, EGL_SERVER_OFPORT). If that
        is wrong, the evidence silently reads 0, so we check it on live traffic.
        """
        # Look at ARP too: the learning switch installs flows from the server's
        # first ARP reply, so its IP packets may never reach the controller.
        ip, arp_pkt = pkt.get_protocol(ipv4.ipv4), pkt.get_protocol(arp.arp)
        src = ip.src if ip else (arp_pkt.src_ip if arp_pkt else None)
        if self._server_seen_at or src != self.cfg.server_ip:
            return
        if dpid != self.cfg.server_dpid:
            return  # seen on another switch first (via the core); keep waiting
        self._server_seen_at = (dpid, in_port)
        if in_port == self.cfg.server_ofport:
            self.logger.info("server %s confirmed on dpid %d port %d",
                             src, dpid, in_port)
        else:
            self.logger.error("server %s is on dpid %d port %d, but "
                              "EGL_SERVER_OFPORT=%d: evidence will be wrong!",
                              src, dpid, in_port, self.cfg.server_ofport)

    # ---------------------------------------------------------- telemetry --
    def _poll_loop(self):
        while True:
            hub.sleep(self.cfg.poll_seconds)
            dp = self.server_dp
            if dp is None:
                continue
            parser, ofp = dp.ofproto_parser, dp.ofproto
            self._pending = {"_t": time.monotonic(), "_wall": time.time()}
            dp.send_msg(parser.OFPFlowStatsRequest(
                dp, table_id=pipeline.TELEMETRY_TABLE,
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY))
            dp.send_msg(parser.OFPPortStatsRequest(dp, 0, self.cfg.server_ofport))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats(self, ev):
        for stat in ev.msg.body:
            name = pipeline.COUNTER_NAMES.get(stat.cookie)
            if name:
                self._pending[name] = self._pending.get(name, 0) + stat.packet_count
        self._pending["_flow"] = True
        self._maybe_close_window()

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats(self, ev):
        for stat in ev.msg.body:
            if stat.port_no == self.cfg.server_ofport:
                # packets the switch SENT to the server = load reaching it
                self._pending["srv_tx"] = stat.tx_packets
        self._pending["_port"] = True
        self._maybe_close_window()

    def _maybe_close_window(self):
        p = self._pending
        if not (p.get("_flow") and p.get("_port")):
            return  # wait for both replies of this poll
        snap = Snapshot(t=p["_t"], counts={k: p.get(k) for k in FIELDS})
        wall = p["_wall"]
        self._pending = {}
        win = self.window.update(snap)
        if win is None:
            return
        self._write_csv(wall, snap, win)
        self.send_event_to_observers(EventTelemetry(win, wall))

    # ---------------------------------------------------------------- CSV --
    COLUMNS = ["wall_time", "dt", *("%s_total" % k for k in FIELDS),
               *("%s_rate" % k for k in FIELDS), "evidence_syn", "completion"]

    def _open_csv(self, path):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        handle = open(path, "w", newline="", encoding="utf-8")
        writer = csv.writer(handle)
        writer.writerow(self.COLUMNS)
        handle.flush()
        return handle, writer

    def _write_csv(self, wall, snap, win):
        handle, writer = self._csv
        writer.writerow([
            "%.3f" % wall, "%.3f" % win.dt,
            *(snap.counts.get(k) or 0 for k in FIELDS),
            *("%.2f" % win.rates[k] for k in FIELDS),
            win.evidence_syn,
            "" if win.completion is None else "%.3f" % win.completion,
        ])
        handle.flush()
