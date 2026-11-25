"""Steps 3-4: run the detectors live, on every telemetry window, side by side.

    ryu-manager --ofp-tcp-listen-port 6653 egl.egl_controller egl.detector_app

(load the apps by MODULE name as above, so both refer to the same
EventTelemetry class)

EGL_DETECTORS lists what to run, e.g. "static,ewma,hst,ewma_egl,hst_egl".
A name ending in "_egl" is that detector wrapped by the Learning Gate
(egl/gate.py): it may learn only when the gate is open -- including during
its warm-up. "_egl_legacy" is the first version, whose warm-up ignored the
gate (kept so experiments can show that limitation next to the fix). Plain and gated copies
see exactly the same windows, so one run compares them fairly.

  EGL_TAU    completion threshold for the gate (default 0.7)
  EGL_DRIFT  optional drift budget per second (default: off)

Nothing here changes the network yet: mitigation comes in step 5. Writes one
CSV row per window (EGL_DETECTOR_CSV) and publishes EventAlarm when a
detector goes from quiet to alarming.
"""

import csv
import os

from ryu.base import app_manager
from ryu.controller import event
from ryu.controller.handler import set_ev_cls

from egl import detectors
from egl.egl_controller import EventTelemetry
from egl.gate import LearningGate


class EventAlarm(event.EventBase):
    """A detector started alarming. Step 5's mitigator listens for this."""

    def __init__(self, detector, wall, rates, anchor):
        super().__init__()
        self.detector, self.wall, self.rates = detector, wall, rates
        self.anchor = anchor   # (median, MAD) SYN rate the gate trusted


def build(names):
    """'ewma,ewma_egl,ewma_egl_legacy' ->
    [('ewma', EWMA(), None), ('ewma_egl', EWMA(), 'egl'), ('ewma_egl_legacy', EWMA(), 'legacy')]"""
    out = []
    for name in (n.strip() for n in names.split(",")):
        if not name:
            continue
        mode, base = None, name
        if name.endswith("_egl_legacy"):
            mode, base = "legacy", name[:-len("_egl_legacy")]
        elif name.endswith("_egl"):
            mode, base = "egl", name[:-len("_egl")]
        out.append((name, detectors.make(base)[0], mode))
    return out


def allow_for(mode, det, gate_open):
    """Is this detector allowed to learn this second?"""
    if mode is None:
        return True                       # plain detector: always learns
    if mode == "legacy" and det.warming:
        return True                       # first version: warm-up ignored the gate
    return gate_open


class EventAlarmCleared(event.EventBase):
    """A detector went from alarming back to quiet."""

    def __init__(self, detector, wall):
        super().__init__()
        self.detector, self.wall = detector, wall


class DetectorApp(app_manager.RyuApp):
    _EVENTS = [EventAlarm, EventAlarmCleared]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dets = build(os.environ.get("EGL_DETECTORS", "static,ewma,hst"))
        drift = os.environ.get("EGL_DRIFT")
        self.gate = LearningGate(tau=float(os.environ.get("EGL_TAU", "0.7")),
                                 drift_per_s=float(drift) if drift else None)
        self.alarming = {name: False for name, _, _ in self.dets}
        path = os.environ.get("EGL_DETECTOR_CSV", "results/egl_detectors.csv")
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._fh = open(path, "w", newline="", encoding="utf-8")
        self._csv = csv.writer(self._fh)
        header = ["wall_time", "syn_rate", "srv_tx_rate", "completion",
                  "gate_open", "gate_reason", "anchor_syn"]
        for name, _, _ in self.dets:
            header += ["%s_%s" % (name, k)
                       for k in ("alarm", "score", "threshold", "learned", "warming")]
        self._csv.writerow(header)
        self._fh.flush()
        self.logger.info("detectors: %s, gate tau=%s drift=%s -> %s",
                         [n for n, _, _ in self.dets], self.gate.tau,
                         self.gate.drift_per_s, path)

    @set_ev_cls(EventTelemetry)
    def _on_window(self, ev):
        w = ev.window
        x = {"syn": w.rates["syn"], "srv_tx": w.rates["srv_tx"]}
        decision = self.gate.decide(x, w.completion)
        anchor = self.gate.anchor
        row = ["%.3f" % ev.wall, "%.2f" % x["syn"], "%.2f" % x["srv_tx"],
               "" if w.completion is None else "%.3f" % w.completion,
               int(decision.open), decision.reason,
               "" if anchor[0] is None else "%.2f" % anchor[0]]
        for name, det, gated in self.dets:
            v = det.observe(x, w.dt, allow_learning=allow_for(gated, det, decision.open))
            row += [int(v.alarm), "%.3f" % v.score,
                    "" if v.threshold is None else "%.3f" % v.threshold,
                    int(v.learned), int(v.warming)]
            if v.alarm and not self.alarming[name]:
                self.logger.warning("ALARM %s: syn=%.1f/s", name, x["syn"])
                self.send_event_to_observers(EventAlarm(name, ev.wall, x, anchor))
            elif self.alarming[name] and not v.alarm:
                self.send_event_to_observers(EventAlarmCleared(name, ev.wall))
            self.alarming[name] = v.alarm
        self._csv.writerow(row)
        self._fh.flush()
