# EGL: Evidence-Gated Learning for SDN DDoS detection

Built one step at a time. The design is in the Project doc
`design_v2_evidence_gated_learning.md`.

| Step | What | Status |
|---|---|---|
| 1 | Two-table OVS pipeline + counter telemetry (x_n, e_n) | **done, tested on real OVS** |
| 2 | Frog-boiling ramp attacker | **done, tested on real OVS** |
| 3 | Detectors: Static, EWMA-z, Half-Space Trees | **done, tested on real OVS** |
| 4 | Learning Gate + anchor baseline | **done, tested on real OVS** |
| 5 | Mitigator (OpenFlow meter) + experiment matrix | next |

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
python3 -m unittest egl.test_telemetry egl.test_attack egl.test_detectors egl.test_gate   # 41 unit tests
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

## Step 3: three detectors, live, side by side

### The idea in plain words
A detector that only looks at traffic volume can be built two ways. It can
learn "normal" once and never change (Static), or keep learning (EWMA,
Half-Space Trees). Step 3 runs all three live on the same measurements and
shows the dilemma the paper is built on:

* **Static** catches the slow attack, but also raises a **false alarm** when
  real users grow (a flash crowd).
* **The adaptive detectors** accept real growth, so a slow attack walks right
  past them.
* In volume terms a slow attack and a flash crowd look the same, so **no
  volume-only detector can tell them apart**. Step 4 adds the evidence that can.

### What was built
| File | Role |
|---|---|
| `detectors.py` | One interface for all detectors: `observe(rates, dt, allow_learning)`. A detector scores the window, then learns from it only if it did not alarm **and** `allow_learning` is true (the hook step 4's gate uses). Static, EWMA, and Half-Space Trees (Tan, Ting & Liu, IJCAI 2011) written from the paper in plain Python: 25 random trees, depth 10, 20-window reference, features log(SYN rate) and log(packets to server). Detectors never see the completion ratio, so any later gain is the gate's alone. |
| `detector_app.py` | Ryu app: listens to step 1's `EventTelemetry`, runs every detector on each window, logs `results/step3_<scenario>_detectors.csv`, publishes `EventAlarm` (for step 5). |
| `scenario.py` | Adds `start_crowd`: legitimate users grow exponentially (3 to 15 in 60 s) on h2-h4, h6-h9. |
| `check_step3.py`, `run_step3.sh` | 60 s warm-up, then abrupt / ramp / crowd; a fresh Ryu per scenario. |
| `plot_step3.py` | The figure `results/step3_detectors.png`. |
| `lib.sh` | Loads Ryu apps by module name (see below), checks Open vSwitch is running, and draws figures with the Ryu env's python (it has matplotlib). |

### Run it
```bash
./egl/run_step3.sh                 # abrupt, crowd, ramp: about 13 minutes
./egl/run_step3.sh kernel crowd    # just one scenario
```

### Result (OVS 3.3.9 userspace datapath, Ryu 4.34; users = 5.8 SYN/s)
| Scenario | Static | EWMA | Half-Space Trees |
|---|---|---|---|
| Attack: abrupt 10x | alarm 1.2 s | alarm 1.2 s | alarm 1.2 s |
| Attack: ramp +0.5 %/s to 10.4x (8 min) | alarm at 2.2x (144 s) | **never** | **never** |
| Legit: users grow 5x in 60 s | **false alarm** at 2.6x (32 s) | quiet | **false alarm** at 2.6x (32 s) |

No detector raised an alarm during any warm-up.

**Simulation sweep** (real baseline noise resampled, paced attacker, 10 seeds per row):

| 10 seeds each | Static | EWMA | HST |
|---|---|---|---|
| Ramp +0.5 %/s | 10/10 alarm @2.4x | 0/10 | 1/10 |
| Ramp +1 %/s | 10/10 @2.4x | 0/10 | 8/10 @2.7x |
| Ramp +2 %/s | 10/10 @2.4x | 0/10 | 10/10 @2.1x |
| **Legit** crowd x5 in 60 s | **10/10 false** | 0/10 | **10/10 false** |
| **Legit** crowd x5 in 180 s | **10/10 false** | 0/10 | **8/10 false** |
| **Legit** growth x2 in 300 s | 0/10 | 0/10 | 3/10 false |

HST resists fast ramps because it compares each second with a 20 s block of
history, but an attacker who knows it simply ramps slower (+0.5 %/s). The
same property makes it false-alarm on real crowds.

### Notes for the paper
* **HST alarms when the attack stops.** In the ramp run, HST raised a few
  alarms right after the attack ended: having learned "10x is normal", the
  sudden return to normal looked anomalous. These come after the attack and
  are not counted as detections. They illustrate the poisoning nicely.
* **HST warm-up.** It needs 40 quiet windows: 20 to build its first reference
  and 20 to calibrate its threshold (0.5 x the lowest calibration score). With
  only 34, an attack inside calibration is learned as normal, so step 3 uses a
  60 s warm-up.
* **Load Ryu apps by module name** (`egl.egl_controller egl.detector_app`),
  not by file path. Then both apps share one copy of `EventTelemetry`, so
  events are delivered.

## Step 4: the Learning Gate (the contribution)

### The idea in plain words
Adaptive detectors decide what to learn by asking "does this look normal?".
A slow attack is built to pass that test. The gate asks a different question:
**"did the server actually finish these connections?"**

The completion ratio e_n (server FINs / client SYNs over 5 s) answers it:
* Real users, even a sudden crowd of them, finish their connections, so
  e_n stays near 1.
* Every spoofed SYN pulls it down: with the attack at m x the users' rate,
  e_n is about 1/m.

A gated detector may learn only while e_n >= tau = 0.7, i.e. until the attack
adds about 43 % on top of the users. After that its idea of "normal" is
frozen, and the rest of the ramp sticks out.

The gate never raises alarms and never changes a detector's alarm rule. It
only controls learning. So it fixes poisoning (missed slow attacks), but not a
detector that alarms on any growth (HST's false alarms on real crowds).

### What was built
| File | Role |
|---|---|
| `gate.py` | `LearningGate.decide(rates, completion)` returns open/closed plus the reason (`evidence`, `low-completion`, `no-traffic`, `too-fast`). It keeps an **anchor**: the median/MAD SYN rate of windows it trusted (the clean rate step 5's mitigator will enforce), and an optional **drift budget** (off by default; for the ablation study). |
| `detector_app.py` | Runs plain and gated copies side by side: `EGL_DETECTORS=static,ewma,hst,ewma_egl,hst_egl`. One gate decision per window; the CSV logs `gate_open`, `gate_reason`, `anchor_syn`. |
| `check_step3.py` | Now generic (`--prefix step4`): reads the detector list from the CSV, reports windows with the gate closed. |
| `plot_step3.py` | `--prefix step4` adds a grey "gate closed" strip. |
| `run_step4.sh` | abrupt, crowd and ramp scenarios. |
| `test_gate.py` | 9 tests, including the paper's claim in miniature. |

### Run it
```bash
./egl/run_step4.sh                 # about 13 minutes; figure: results/step4_detectors.png
EGL_TAU=0.5 ./egl/run_step4.sh     # try another threshold
```

### Result (OVS 3.3.9 userspace datapath, Ryu 4.34; users = 5.8-5.9 SYN/s)
| Scenario | Static | EWMA | HST | **EWMA + gate** | HST + gate |
|---|---|---|---|---|---|
| Attack: abrupt 10x | 0.7 s | 0.7 s | 0.7 s | 0.7 s | 0.7 s |
| Attack: ramp +0.5 %/s to 10.4x | 2.21x (144 s) | never | never | **2.89x (200 s)** | 1.87x (109 s) |
| Legit: users grow 5x in 60 s | false alarm 2.56x | quiet | false alarm 2.05x | **quiet** | false alarm 2.05x |

* **EWMA + gate is the only detector that catches the slow attack and stays
  quiet for real users.**
* The gate closed 72 s into the ramp, at 1.43x, exactly where 1/m falls below
  0.7. It stayed open throughout the flash crowd (0 closed windows) and
  through every warm-up.
* The theory predicted EWMA + gate would alarm at about 2.9x after about
  213 s. Live: 2.89x at 200 s.
* An abrupt flood's first alarm window only partly overlaps the attack, hence
  "2.57x" in the JSON at 0.7 s.

### Notes for the paper
* **The gate stays closed briefly after a flood ends** (visible after the
  abrupt attack): half-open entries are still being retried, so completion
  takes a few seconds to recover. Learning simply resumes then. Nothing is
  lost, and no false alarm results.
* **HST + gate catches the ramp earliest (1.87x)** but still false-alarms on
  crowds. Its alarm rule is the limit, not its learning, so the gate
  complements an adaptive detector rather than replacing a good one.
