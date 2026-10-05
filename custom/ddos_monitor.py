#!/usr/bin/env python3

import csv
import json
import os
import statistics
import time
from datetime import datetime, timezone

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import DEAD_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3

from ddos_events import EventMitigationRequest


class DDoSMonitor(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.datapaths = {}
		self.port_stats = {}
		self.flow_stats = {}
		self.packet_in_counts = {}
		self.previous_port_stats = {}
		self.previous_flows = {}
		self.previous_packet_ins = {}
		self.baseline_seconds = float(
			os.environ.get("DDOS_BASELINE_SECONDS", "30")
		)
		self.detector_threshold = float(
			os.environ.get("DDOS_DETECTOR_THRESHOLD", "3")
		)
		self.required_consecutive = int(
			os.environ.get("DDOS_REQUIRED_CONSECUTIVE", "2")
		)
		self.baseline_started_at = None
		self.baseline_values = {}
		self.baseline_stats = {}
		self.anomaly_state = {}
		self.anomaly_streak = {}
		self.mitigation_requested = False
		self.controller_app = os.environ.get(
			"DDOS_CONTROLLER_APP",
			"custom/ryu_ddos_controller.py",
		)
		self.attacker_ip = os.environ.get("DDOS_ATTACKER_IP", "10.0.0.1")
		self.victim_ip = os.environ.get("DDOS_VICTIM_IP", "10.0.0.10")
		self.output_path = os.environ.get(
			"DDOS_MONITOR_OUTPUT",
			"ddos_metrics.csv",
		)
		self.control_path = os.environ.get(
			"DDOS_RUN_CONTROL",
			"/home/anirudh/mininet/results/current_run.json",
		)
		self.monitor_thread = hub.spawn(self._monitor)

	@set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
	def state_change_handler(self, ev):
		datapath = ev.datapath
		if ev.state == MAIN_DISPATCHER:
			self.datapaths[datapath.id] = datapath
		elif ev.state == DEAD_DISPATCHER:
			dpid = getattr(datapath, "id", None)
			if dpid is None:
				self.logger.debug("Switch disconnected without a datapath ID")
				return

			self.datapaths.pop(dpid, None)
			self.port_stats.pop(dpid, None)
			self.flow_stats.pop(dpid, None)
			self.packet_in_counts.pop(dpid, None)

			# Remove historical state for this switch
			for key in list(self.previous_port_stats):
				if key[0] == dpid:
					del self.previous_port_stats[key]

			if hasattr(self, "previous_flows"):
				self.previous_flows.pop(dpid, None)

			if hasattr(self, "previous_packet_ins"):
				self.previous_packet_ins.pop(dpid, None)

			self.baseline_values.pop(dpid, None)
			self.baseline_stats.pop(dpid, None)
			self.anomaly_state.pop(dpid, None)
			self.anomaly_streak.pop(dpid, None)

			self.logger.info("Switch disconnected: s%d", dpid)

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def packet_in_handler(self, ev):
		dpid = ev.msg.datapath.id
		self.packet_in_counts[dpid] = self.packet_in_counts.get(dpid, 0) + 1

	@set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
	def port_stats_reply_handler(self, ev):
		now = time.monotonic()
		stats = {}
		for stat in ev.msg.body:
			stats[stat.port_no] = {
				"rx_packets": stat.rx_packets,
				"tx_packets": stat.tx_packets,
				"rx_bytes": stat.rx_bytes,
				"tx_bytes": stat.tx_bytes,
				"timestamp": now,
			}
		self.port_stats[ev.msg.datapath.id] = stats

	@set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
	def flow_stats_reply_handler(self, ev):
		flows = {}
		for stat in ev.msg.body:
			if stat.priority == 0:
				continue
			flow_key = (
				stat.table_id,
				stat.priority,
				stat.cookie,
				str(stat.match),
			)
			flows[flow_key] = stat
		self.flow_stats[ev.msg.datapath.id] = flows

	def _monitor(self):
		while True:
			for datapath in list(self.datapaths.values()):
				self._request_port_stats(datapath)
				self._request_flow_stats(datapath)
			hub.sleep(1)
			self._write_samples()

	@staticmethod
	def _request_port_stats(datapath):
		parser = datapath.ofproto_parser
		request = parser.OFPPortStatsRequest(
			datapath,
			0,
			datapath.ofproto.OFPP_ANY,
		)
		datapath.send_msg(request)

	@staticmethod
	def _request_flow_stats(datapath):
		parser = datapath.ofproto_parser
		request = parser.OFPFlowStatsRequest(datapath)
		datapath.send_msg(request)

	def _write_samples(self):
		self._sync_run_output()
		timestamp = datetime.now(timezone.utc).isoformat()
		monotonic_now = time.monotonic()
		port_samples = {}
		switch_metrics = {}
		for dpid, ports in self.port_stats.items():
			current_flows = self.flow_stats.get(dpid, {})
			previous_flows = self.previous_flows.get(dpid, {})
			new_flows = len(set(current_flows) - set(previous_flows))
			self.previous_flows[dpid] = current_flows

			current_packet_ins = self.packet_in_counts.get(dpid, 0)
			previous_packet_ins = self.previous_packet_ins.get(dpid, 0)
			self.previous_packet_ins[dpid] = current_packet_ins
			port_samples[dpid] = []
			total_rx_packets = 0
			total_tx_packets = 0
			intervals = []

			for port_no, current in ports.items():
				previous = self.previous_port_stats.get((dpid, port_no))
				interval = 1.0 if previous is None else max(
					current["timestamp"] - previous["timestamp"],
					0.001,
				)
				rx_packets = self._delta(current, previous, "rx_packets")
				tx_packets = self._delta(current, previous, "tx_packets")
				rx_bytes = self._delta(current, previous, "rx_bytes")
				tx_bytes = self._delta(current, previous, "tx_bytes")
				total_rx_packets += rx_packets
				total_tx_packets += tx_packets
				intervals.append(interval)
				port_samples[dpid].append(
					{
						"port": port_no,
						"current": current,
						"rx_packets": rx_packets,
						"tx_packets": tx_packets,
						"rx_bytes": rx_bytes,
						"tx_bytes": tx_bytes,
						"interval": interval,
						"active_flows": len(current_flows),
						"new_flows": new_flows,
						"packet_ins": current_packet_ins - previous_packet_ins,
					}
				)
				self.previous_port_stats[(dpid, port_no)] = current

			interval = max(intervals, default=1.0)
			switch_metrics[dpid] = {
				"packet_rate": (total_rx_packets + total_tx_packets) / interval,
				"new_flow_rate": new_flows / interval,
				"packet_in_rate": (current_packet_ins - previous_packet_ins) / interval,
				"active_flows": len(current_flows),
			}

		if switch_metrics and self.baseline_started_at is None:
			self.baseline_started_at = monotonic_now
		baseline_complete = (
			self.baseline_started_at is not None
			and monotonic_now - self.baseline_started_at >= self.baseline_seconds
		)
		for dpid, metrics in switch_metrics.items():
			if not baseline_complete:
				self.baseline_values.setdefault(
					dpid,
					{"packet_rate": [], "new_flow_rate": [], "packet_in_rate": []},
				)
				for metric_name in ("packet_rate", "new_flow_rate", "packet_in_rate"):
					self.baseline_values[dpid][metric_name].append(
						metrics[metric_name]
					)
				metrics.update(
					{
						"packet_rate_z": 0.0,
						"new_flow_rate_z": 0.0,
						"packet_in_rate_z": 0.0,
						"suspicious": False,
						"anomaly_streak": 0,
						"anomaly": False,
					}
				)
			elif dpid not in self.baseline_stats:
				self.baseline_stats[dpid] = {}
				for metric_name in ("packet_rate", "new_flow_rate", "packet_in_rate"):
					values = self.baseline_values.get(dpid, {}).get(metric_name, [0.0])
					mean = statistics.mean(values)
					std = statistics.pstdev(values) or 1.0
					self.baseline_stats[dpid][metric_name] = (mean, std)
				self.logger.info(
					"Baseline established for s%d: %d samples",
					dpid,
					len(self.baseline_values.get(dpid, {}).get("packet_rate", [])),
				)

			if baseline_complete:
				z_scores = {}
				for metric_name in ("packet_rate", "new_flow_rate", "packet_in_rate"):
					mean, std = self.baseline_stats[dpid][metric_name]
					z_scores[metric_name + "_z"] = (
						metrics[metric_name] - mean
					) / std
				metrics.update(z_scores)
				metrics["suspicious"] = any(
					z_scores[name] > self.detector_threshold
					for name in (
						"packet_rate_z",
						"new_flow_rate_z",
						"packet_in_rate_z",
					)
				)
				if metrics["suspicious"]:
					self.anomaly_streak[dpid] = self.anomaly_streak.get(dpid, 0) + 1
				else:
					self.anomaly_streak[dpid] = 0
				metrics["anomaly_streak"] = self.anomaly_streak[dpid]
				metrics["anomaly"] = (
					self.anomaly_streak[dpid] >= self.required_consecutive
				)
				if metrics["anomaly"] and not self.anomaly_state.get(dpid, False):
					self.logger.warning(
						"Lightweight anomaly trigger on s%d: packet=%.2f, flows=%.2f, packet-in=%.2f",
						dpid,
						metrics["packet_rate_z"],
						metrics["new_flow_rate_z"],
						metrics["packet_in_rate_z"],
					)
					if not self.mitigation_requested:
						self.send_event(
							self.controller_app,
							EventMitigationRequest(
								self.attacker_ip,
								self.victim_ip,
							),
						)
						self.mitigation_requested = True
				self.anomaly_state[dpid] = metrics["anomaly"]

		file_exists = os.path.exists(self.output_path)
		with open(self.output_path, "a", newline="", encoding="utf-8") as output:
			fieldnames = [
				"timestamp",
				"switch_id",
				"port",
				"rx_packets",
				"tx_packets",
				"rx_bytes",
				"tx_bytes",
				"rx_pps",
				"tx_pps",
				"rx_mbps",
				"tx_mbps",
				"active_flows",
				"new_flows_per_second",
				"packet_in_per_second",
				"packet_rate",
				"new_flow_rate",
				"packet_in_rate",
				"packet_rate_z",
				"new_flow_rate_z",
				"packet_in_rate_z",
				"suspicious",
				"anomaly_streak",
				"anomaly",
			]
			writer = csv.DictWriter(
				output,
				fieldnames=fieldnames,
				lineterminator="\n",
			)
			if not file_exists or os.path.getsize(self.output_path) == 0:
				writer.writeheader()
			for dpid, samples in port_samples.items():
				metrics = switch_metrics[dpid]
				for port_sample in samples:
					current = port_sample["current"]
					interval = port_sample["interval"]
					sample = {
						"timestamp": timestamp,
						"switch_id": dpid,
						"port": port_sample["port"],
						"rx_packets": current["rx_packets"],
						"tx_packets": current["tx_packets"],
						"rx_bytes": current["rx_bytes"],
						"tx_bytes": current["tx_bytes"],
						"rx_pps": port_sample["rx_packets"] / interval,
						"tx_pps": port_sample["tx_packets"] / interval,
						"rx_mbps": port_sample["rx_bytes"] * 8 / interval / 1000000,
						"tx_mbps": port_sample["tx_bytes"] * 8 / interval / 1000000,
						"active_flows": metrics["active_flows"],
						"new_flows_per_second": metrics["new_flow_rate"],
						"packet_in_per_second": metrics["packet_in_rate"],
						"packet_rate": metrics["packet_rate"],
						"new_flow_rate": metrics["new_flow_rate"],
						"packet_in_rate": metrics["packet_in_rate"],
						"packet_rate_z": metrics["packet_rate_z"],
						"new_flow_rate_z": metrics["new_flow_rate_z"],
						"packet_in_rate_z": metrics["packet_in_rate_z"],
						"suspicious": metrics["suspicious"],
						"anomaly_streak": metrics["anomaly_streak"],
						"anomaly": metrics["anomaly"],
					}
					writer.writerow(sample)
			output.flush()

	def _delta(self, current, previous, field):
		if previous is None:
			return 0
		return max(current[field] - previous[field], 0)

	def _sync_run_output(self):
		if not os.path.exists(self.control_path):
			return
		try:
			with open(self.control_path, encoding="utf-8") as control_file:
				control = json.load(control_file)
			metrics_path = control.get("metrics_path")
			if metrics_path:
				self.output_path = metrics_path
		except (OSError, json.JSONDecodeError):
			self.logger.debug("Unable to read run control file", exc_info=True)

	def close(self):
		hub.kill(self.monitor_thread)
		super().close()
