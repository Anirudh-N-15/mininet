# EGL: Evidence-Gated Learning for SDN DDoS detection

Built one step at a time. The design is in the Project doc
`design_v2_evidence_gated_learning.md`.

| Step | What | Status |
|---|---|---|
| 1 | Two-table OVS pipeline + counter telemetry (x_n, e_n) | **done, tested on real OVS** |
| 2 | Frog-boiling ramp attacker | **done, tested on real OVS** |
| 3 | Detectors: Static, EWMA-z, Half-Space Trees | next |
| 4 | Learning Gate + anchor baseline | |
| 5 | Mitigator (OpenFlow meter) + experiment matrix | |

## Step 1: what was built

### The idea in plain words
Before anything can detect or defend, the controller needs two numbers every
second, measured cheaply and in a way an attacker cannot fake:

* **x_n, SYN rate:** how many new connection attempts hit the server per second.
  This is what the detector will watch.
* **e_n, completion ratio:** server FINs ÷ client SYNs over the last 5 s.
  Real users finish their connections (≈ 1). A SYN flood never does (≈ 0). This
  is the evidence the learning gate will trust.

### How the switch is organised (pipeline.py)
```
packet ─► TABLE 0 "count"                         ─► TABLE 1 "forward"
          R_SYN   client SYN to server  (count)        normal MAC learning
          R_FIN   server FIN, server port (count)       (unknown dst → Ryu)
          R_SA    server SYN-ACK        (count)
          default anything else
          every rule ends with: goto table 1
```
* **Counting never changes forwarding.** Every table-0 rule just counts and
  hands the packet to table 1.
* **The rules don't overlap.** A packet matches only one rule per table, so
  they differ by direction (to / from the server) and by TCP flags.
  `tcp_flags=(SYN, SYN|ACK)` means "SYN bit set, ACK bit clear", i.e. a
  client's attempt and not the server's reply.
* **The FIN rule is pinned to the server's own switch port** (`in_port=6` on
  s2). Anything arriving on that cable comes from the server, so an attacker
  elsewhere cannot inject fake FINs to look "complete".
* **No Packet-In for telemetry.** The controller reads counters once per second
  (one flow-stats and one port-stats request), whatever the attack size.

### Files
| File | Role |
|---|---|
| `config.py` | Every tunable (server IP/port, switch/port, poll interval, evidence window) from env vars |
| `pipeline.py` | The table-0 counting rules as plain data (TCP flag bits, cookies) |
| `telemetry.py` | Cumulative counters → per-window rates + completion ratio; handles counter resets and "too few SYNs = no evidence" |
| `egl_controller.py` | Ryu app: installs both tables, MAC learning in table 1, polls counters, writes `results/egl_telemetry.csv`, publishes `EventTelemetry` for later steps, checks that the server really is on the configured port |
| `topology.py` | s1(h1–h5) — s3 — s2(h6–h10); server h10 = s2 port 6 |
| `check_step1.py` | Acceptance test in Mininet |
| `run_step1.sh` | One command: Ryu + test + cleanup |
| `test_telemetry.py` | 9 unit tests (no Ryu/Mininet needed) |

### Run it
```bash
python3 -m unittest egl.test_telemetry egl.test_attack   # unit tests, no sudo
./egl/run_step1.sh                          # real network, about 50 s
./egl/run_step1.sh user                     # if OVS kernel module is missing
```
Timeline: 15 s of 3 users (curl, 2 req/s each) → 15 s users + spoofed SYN flood
(hping3 `--rand-source`, 200 pps) → 10 s users only.

### Result (OVS 3.3.9 userspace datapath, Ryu 4.34)
| Phase | SYN/s | Completion e_n |
|---|---|---|
| users only | 5.8 | 1.000 |
| users + flood | 199.9 | 0.029 |
| users only again | 6.0 | 1.000 |

The SYN rate matches 3 users × 2 req/s, then the flood. The completion ratio
separates the two cleanly and recovers once the flood stops. The test passes.
A deliberately wrong `EGL_SERVER_OFPORT` is caught with an error naming the
real port.

### Things learned while testing (worth a line in the paper's setup section)
* **OVS userspace datapath + veth drops TCP:** veth leaves TCP checksums for
  "hardware" offload, the userspace datapath never fills them in, and the
  receiver discards the packets (ping still works). Fix: `ethtool -K <if> tx off`
  on hosts. The kernel datapath is not affected.
* **Counter lag:** OVS refreshes per-rule counters from its fast-path cache
  about every 0.5 s, so a counter read right after traffic can be slightly
  behind. This is harmless at 1 s polling.
* **ARP, not IP, reveals the server's port:** the learning switch installs
  flows from the server's first ARP reply, so its IP packets never reach Ryu.
  The location check therefore also reads ARP.
* **e_n can read slightly above 1** for a window or two after a phase change,
  when FINs land in a window whose SYNs fell in the previous one.

## Step 2: the frog-boiling attacker

### The idea in plain words
An adaptive detector keeps re-learning what "normal" looks like. If the flood
grows slowly enough, every second looks only a little above normal, so the
detector learns it. Step 2 builds that attacker and checks the claim on a real
network: **a 10x SYN flood that creeps up at +2 %/s is never flagged, while the
same 10x flood arriving at once is flagged within about a second.**

### What was built
| File | Role |
|---|---|
| `attack.py` | The schedules, as maths: abrupt = jump to 10x; ramp = total rate x (1.02)^t up to 10x (10x after ln 10 / ln 1.02 = 116 s). `Pacer` turns a changing rate into "send n packets now" without losing fractions. |
| `syn_sender.py` | Raw-socket SYN generator (random spoofed source IP, port, sequence number; correct checksums). It follows the schedule continuously and logs what it really sent each second. |
| `detectors.py` | EWMA-z, the adaptive detector of recent SDN papers. It learns only from windows it calls normal (the rule the ramp abuses), with a Poisson noise floor sqrt(mu) because SYN rates are counts. |
| `scenario.py` | Shared network setup for all steps (see below). |
| `web_server.py` | The protected server: http.server with a realistic 511 backlog (nginx/Apache default). |
| `check_step2.py` | 40 s of users, then the attack; replays the measured SYN rate through EWMA-z; writes `results/step2_<mode>.json` and `_trace.csv`. |
| `plot_step2.py` | The figure `results/step2_ramp_vs_abrupt.png`. |
| `lib.sh` | Shared Ryu start/stop for the run scripts; passes variables to sudo explicitly (newer sudo ignores `-E`). |

**Why not hping3 for the ramp:** its rate is fixed for the whole run, and one
hping3 per second fails because it lingers after its last packet (100 packets
meant for 1 s took 2.0 s). hping3 is still used for constant floods (step 1).

### Run it
```bash
./egl/run_step2.sh            # abrupt then ramp, about 4.5 minutes
python3 -m egl.plot_step2     # draws the figure from the results
```

### Result (OVS 3.3.9 userspace datapath, Ryu 4.34; users = 5.85 +/- 0.49 SYN/s)
| Attack | Measured / sent | Reached | EWMA alarms | First alarm |
|---|---|---|---|---|
| abrupt 10x | 0.98 | 9.7x | 31 | 1.2 s after start |
| ramp +2 %/s | 0.993 | **10.3x** | **0** | never |

### Realism fixes made in this step (they also apply to step 1)
* **The server can now answer spoofed SYNs.** Its default route points at a
  made-up gateway pinned to h5's MAC. Before, it had no route, so the kernel
  discarded spoofed SYNs without holding them half-open, which understated the
  flood's damage.
* **A realistic listen backlog (511) instead of http.server's 5.**
* **Linux keeps admitting known clients under a flood.** With SYN cookies off,
  once the half-open queue is 3/4 full (384 of 512) the kernel drops SYNs from
  unfamiliar addresses but still admits clients it recently completed
  connections with. Our returning users kept working (2 ms connects) while
  1,005 flood SYNs were dropped; a brand-new visitor would be locked out.
* **Step 1's recovery is now reported, not required.** Half-open entries live
  about 63 s (SYN-ACK retries at 1+2+4+8+16+32 s), so a server can stay
  clogged after the flood stops.
* **One-window dips in the trace** (e.g. 24 SYN/s where about 45 arrived) come
  from OVS refreshing rule counters on its own timer, not from the attacker,
  which logged 43 sent that second. This is noted as a measurement limitation.
