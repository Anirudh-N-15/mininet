"""Step 3: run the detectors live, on every telemetry window, side by side.

    ryu-manager --ofp-tcp-listen-port 6653 egl.egl_controller egl.detector_app

(load the apps by MODULE name as above, so both refer to the same
EventTelemetry class)

For each window from egl_controller (EventTelemetry) every detector in
EGL_DETECTORS (default "static,ewma,hst") scores it and maybe learns from it.
All detectors see exactly the same numbers, so one run compares them fairly.
None of them changes the network yet: mitigation comes in step 5.

Writes one CSV row per window (EGL_DETECTOR_CSV) and publishes EventAlarm
when a detector goes from quiet to alarming.
"""

import csv
import os

from ryu.base import app_manager
from ryu.controller import event
from ryu.controller.handler import set_ev_cls

from egl import detectors
from egl.egl_controller import EventTelemetry


class EventAlarm(event.EventBase):
    """A detector started alarming. Step 5's mitigator listens for this."""

    def __init__(self, detector, wall, rates):
        super().__init__()
        self.detector, self.wall, self.rates = detector, wall, rates


class DetectorApp(app_manager.RyuApp):
    _EVENTS = [EventAlarm]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dets = detectors.make(os.environ.get("EGL_DETECTORS", "static,ewma,hst"))
        self.alarming = {d.name: False for d in self.dets}
        path = os.environ.get("EGL_DETECTOR_CSV", "results/egl_detectors.csv")
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._fh = open(path, "w", newline="", encoding="utf-8")
        self._csv = csv.writer(self._fh)
        header = ["wall_time", "syn_rate", "srv_tx_rate", "completion"]
        for d in self.dets:
            header += ["%s_%s" % (d.name, k)
                       for k in ("alarm", "score", "threshold", "learned", "warming")]
        self._csv.writerow(header)
        self._fh.flush()
        self.logger.info("detectors: %s -> %s", [d.name for d in self.dets], path)

    @set_ev_cls(EventTelemetry)
    def _on_window(self, ev):
        w = ev.window
        x = {"syn": w.rates["syn"], "srv_tx": w.rates["srv_tx"]}
        row = ["%.3f" % ev.wall, "%.2f" % x["syn"], "%.2f" % x["srv_tx"],
               "" if w.completion is None else "%.3f" % w.completion]
        for d in self.dets:
            v = d.observe(x, w.dt, allow_learning=True)   # step 4 gates this
            row += [int(v.alarm), "%.3f" % v.score,
                    "" if v.threshold is None else "%.3f" % v.threshold,
                    int(v.learned), int(v.warming)]
            if v.alarm and not self.alarming[d.name]:
                self.logger.warning("ALARM %s: syn=%.1f/s", d.name, x["syn"])
                self.send_event_to_observers(EventAlarm(d.name, ev.wall, x))
            self.alarming[d.name] = v.alarm
        self._csv.writerow(row)
        self._fh.flush()
