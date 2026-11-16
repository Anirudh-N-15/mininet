"""Step 5: act on alarms -- rate-limit unverified SYNs, let verified clients through.

    ryu-manager --ofp-tcp-listen-port 6653 egl.egl_controller egl.detector_app \
        egl.mitigator_app          (with EGL_VERIFY_CLIENTS=1)

The same unforgeable evidence the Learning Gate uses -- FINs sent by the
server, arriving on the server's own switch port -- also tells us WHO finished
a connection: the FIN's destination. Those clients are "verified".

When the chosen detector (EGL_MITIGATE_ON, e.g. "ewma_egl") starts alarming:
  1. an OpenFlow meter limits client SYNs to the server to
     max(EGL_METER_MIN, EGL_METER_MARGIN x the gate's clean anchor rate)
     packets/s, dropping the rest at the switch;
  2. if EGL_BYPASS=1 (default), every verified client gets a higher-priority
     rule that sends its SYNs past the meter. New verified clients are added
     while the attack is on. Spoofed sources can never be verified: a spoofed
     SYN never completes, so the server never sends it a FIN.
When the detector has been quiet for EGL_RELEASE_SECONDS, everything is
removed again.

EGL_MITIGATE_ON=none disables mitigation (the "no defence" baseline).
EGL_BYPASS=0 gives the plain meter (ablation: rate limit without evidence).

Logs to EGL_MITIGATION_CSV: one row per second (meter drops, verified
clients, bypass rules) plus one row per action.
"""

import csv
import os
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ipv4, packet

from egl import pipeline
from egl.detector_app import EventAlarm, EventAlarmCleared

METER_ID = 1


class MitigatorApp(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        env = os.environ.get
        self.target = env("EGL_MITIGATE_ON", "ewma_egl")
        self.bypass = env("EGL_BYPASS", "1") == "1"
        self.margin = float(env("EGL_METER_MARGIN", "1.5"))
        self.min_rate = float(env("EGL_METER_MIN", "5"))
        self.release_s = float(env("EGL_RELEASE_SECONDS", "10"))
        self.verified_ttl = float(env("EGL_VERIFIED_TTL", "600"))
        self.verified = {}         # client ip -> last time it finished a connection
        self.bypassed = set()      # ips that currently have a bypass rule
        self.active = False
        self.rate = None
        self._quiet_since = None
        self._dropped = 0
        path = env("EGL_MITIGATION_CSV", "results/egl_mitigation.csv")
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._fh = open(path, "w", newline="", encoding="utf-8")
        self._csv = csv.writer(self._fh)
        self._csv.writerow(["wall_time", "event", "active", "meter_rate",
                            "meter_dropped_total", "verified", "bypass_rules", "detail"])
        self.logger.info("mitigator: on=%s bypass=%s margin=%s min=%s",
                         self.target, self.bypass, self.margin, self.min_rate)
        hub.spawn(self._tick)

    # ---------------------------------------------------------- helpers --
    @property
    def ctl(self):
        return app_manager.lookup_service_brick("EGLController")

    def _log(self, event, detail=""):
        self._csv.writerow(["%.3f" % time.time(), event, int(self.active),
                            "" if self.rate is None else "%.1f" % self.rate,
                            self._dropped, len(self.verified), len(self.bypassed), detail])
        self._fh.flush()

    def _syn_rule(self, dp, with_meter):
        """Re-write the SYN counting rule; MODIFY_STRICT keeps its counters."""
        ofp, parser = dp.ofproto, dp.ofproto_parser
        inst = [parser.OFPInstructionGotoTable(pipeline.FORWARD_TABLE)]
        if with_meter:
            inst.insert(0, parser.OFPInstructionMeter(METER_ID))
        dp.send_msg(parser.OFPFlowMod(
            dp, table_id=pipeline.TELEMETRY_TABLE, command=ofp.OFPFC_MODIFY_STRICT,
            priority=100, match=parser.OFPMatch(**pipeline.syn_fields(self.ctl.cfg)),
            instructions=inst))

    def _add_bypass(self, dp, ip):
        parser = dp.ofproto_parser
        fields = dict(pipeline.syn_fields(self.ctl.cfg), ipv4_src=ip)
        dp.send_msg(parser.OFPFlowMod(
            dp, table_id=pipeline.TELEMETRY_TABLE, priority=110,
            cookie=pipeline.COOKIE_BYPASS, match=parser.OFPMatch(**fields),
            instructions=[parser.OFPInstructionGotoTable(pipeline.FORWARD_TABLE)]))
        self.bypassed.add(ip)

    # ------------------------------------------- learn verified clients --
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _fin_copy(self, ev):
        msg = ev.msg
        if msg.cookie != pipeline.COOKIE_FIN:
            return
        ip = packet.Packet(msg.data).get_protocol(ipv4.ipv4)
        if ip is None:
            return
        client = ip.dst
        self.verified[client] = time.time()
        dp = self.ctl.server_dp if self.ctl else None
        if self.active and self.bypass and dp is not None and client not in self.bypassed:
            self._add_bypass(dp, client)

    # ---------------------------------------------------------- actions --
    @set_ev_cls(EventAlarm)
    def _on_alarm(self, ev):
        if ev.detector != self.target:
            return
        self._quiet_since = None
        if self.active:
            return
        dp = self.ctl.server_dp if self.ctl else None
        if dp is None:
            return
        anchor = ev.anchor[0] if ev.anchor and ev.anchor[0] else None
        self.rate = max(self.min_rate, self.margin * anchor) if anchor else self.min_rate
        ofp, parser = dp.ofproto, dp.ofproto_parser
        dp.send_msg(parser.OFPMeterMod(
            dp, command=ofp.OFPMC_ADD, flags=ofp.OFPMF_PKTPS | ofp.OFPMF_BURST,
            meter_id=METER_ID,
            bands=[parser.OFPMeterBandDrop(rate=max(1, int(round(self.rate))),
                                           burst_size=max(1, int(round(self.rate))))]))
        self._syn_rule(dp, with_meter=True)
        self.active = True
        if self.bypass:
            now = time.time()
            for ip, seen in list(self.verified.items()):
                if now - seen <= self.verified_ttl:
                    self._add_bypass(dp, ip)
        self.logger.warning("MITIGATION ON (%s): unverified SYNs limited to %.1f/s, "
                            "%d verified clients bypass", ev.detector, self.rate,
                            len(self.bypassed))
        self._log("on", "anchor=%s" % anchor)

    @set_ev_cls(EventAlarmCleared)
    def _on_clear(self, ev):
        if ev.detector == self.target and self.active:
            self._quiet_since = time.time()

    def _release(self):
        dp = self.ctl.server_dp if self.ctl else None
        if dp is not None:
            ofp, parser = dp.ofproto, dp.ofproto_parser
            self._syn_rule(dp, with_meter=False)
            dp.send_msg(parser.OFPFlowMod(
                dp, table_id=pipeline.TELEMETRY_TABLE, command=ofp.OFPFC_DELETE,
                cookie=pipeline.COOKIE_BYPASS, cookie_mask=0xFFFFFFFFFFFFFFFF,
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY))
            dp.send_msg(parser.OFPMeterMod(dp, command=ofp.OFPMC_DELETE,
                                           meter_id=METER_ID))
        self.active = False
        self.bypassed.clear()
        self._quiet_since = None
        self.logger.warning("MITIGATION OFF")
        self._log("off")

    # ------------------------------------------------- once per second --
    def _tick(self):
        while True:
            hub.sleep(1.0)
            ctl = self.ctl
            dp = ctl.server_dp if ctl else None
            if self.active and self._quiet_since is not None \
                    and time.time() - self._quiet_since >= self.release_s:
                self._release()
            if self.active and dp is not None:
                dp.send_msg(dp.ofproto_parser.OFPMeterStatsRequest(dp, 0, METER_ID))
            self._log("tick")

    @set_ev_cls(ofp_event.EventOFPMeterStatsReply, MAIN_DISPATCHER)
    def _meter_stats(self, ev):
        for stat in ev.msg.body:
            if stat.meter_id == METER_ID and stat.band_stats:
                self._dropped = stat.band_stats[0].packet_band_count
