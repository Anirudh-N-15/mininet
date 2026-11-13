"""All tunables for the EGL controller, read once from environment variables.

Keeping every knob here (instead of scattered os.environ calls) means the paper's
"experimental setup" table can be generated from one place.
"""

import os
from dataclasses import dataclass


def _env(name, default, cast=str):
    value = os.environ.get(name)
    return default if value in (None, "") else cast(value)


@dataclass(frozen=True)
class EGLConfig:
    # --- the protected service ---------------------------------------------
    server_ip: str          # IP of the web server we protect (h10)
    server_tcp_port: int    # its listening port
    server_dpid: int        # switch the server is plugged into (s2 -> dpid 2)
    server_ofport: int      # that switch's port facing the server (h10 -> 6)
    # --- telemetry ----------------------------------------------------------
    poll_seconds: float     # how often counters are read (one window = one poll)
    evidence_seconds: float # completion ratio is measured over this sliding window
    min_syn_for_evidence: int  # fewer SYNs than this in the window -> "no evidence"
    telemetry_csv: str      # where every window is logged

    @classmethod
    def from_env(cls):
        return cls(
            server_ip=_env("EGL_SERVER_IP", "10.0.0.10"),
            server_tcp_port=_env("EGL_SERVER_TCP_PORT", 80, int),
            server_dpid=_env("EGL_SERVER_DPID", 2, int),
            server_ofport=_env("EGL_SERVER_OFPORT", 6, int),
            poll_seconds=_env("EGL_POLL_SECONDS", 1.0, float),
            evidence_seconds=_env("EGL_EVIDENCE_SECONDS", 5.0, float),
            min_syn_for_evidence=_env("EGL_MIN_SYN_EVIDENCE", 3, int),
            telemetry_csv=_env("EGL_TELEMETRY_CSV", "results/egl_telemetry.csv"),
        )
