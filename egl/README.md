# EGL: Evidence-Gated Learning for SDN DDoS detection

Built one step at a time. The design is in the Project doc
`design_v2_evidence_gated_learning.md`.

| Step | What | Status |
|---|---|---|
| 1 | Two-table OVS pipeline + counter telemetry (x_n, e_n) | **done, tested on real OVS** |
| 2 | Frog-boiling ramp attacker | **done, tested on real OVS** |
| 3 | Detectors: Static, EWMA-z, Half-Space Trees | **done, tested on real OVS** |
| 4 | Learning Gate + anchor baseline | **done, tested on real OVS** |
| 5a | Mitigation: SYN meter + verified-client bypass | **done, tested on real OVS** |
| 5b | Evaluation matrix: repeats, tau sweep, ablations, limitation case | next |

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
python3 -m unittest egl.test_telemetry egl.test_attack egl.test_detectors egl.test_gate egl.test_mitigation egl.test_eval   # 57 unit tests
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

## Step 5a: mitigation that protects the server without hurting users

### The idea in plain words
When the detector alarms, the switch should stop the flood. The obvious tool
is a **SYN meter**: let at most N connection attempts per second through.
But a meter can't tell users from attackers. During a 10x flood, about 9 in
10 SYNs are fake, so it mostly blocks real users too.

The gate's evidence fixes this. A FIN sent by the server, arriving on the
server's own cable, proves that its destination **finished a real
connection**. Those clients are **verified**. During an attack:

* SYNs from verified clients **bypass** the meter (one higher-priority rule each);
* every other SYN is metered to 1.5 x the gate's clean anchor rate (9/s here).

A spoofed address can never be verified, because a spoofed SYN never
completes. So the attacker cannot get on the bypass list.

### What was built
| File | Role |
|---|---|
| `mitigator_app.py` | Ryu app. Learns verified clients from FIN copies. On `EventAlarm` from the chosen detector it adds the meter and a bypass rule per verified client (and for clients verified later). It removes everything 10 s after the alarm clears. Logs meter drops each second. Policy via `EGL_MITIGATE_ON` (`none`, `static`, `ewma_egl`, ...) and `EGL_BYPASS` (1 bypass, 0 plain meter). |
| `egl_controller.py` | With `EGL_VERIFY_CLIENTS=1` the FIN rule also copies 128 bytes of each server FIN to Ryu. These are only completed connections, a few per second, and an attacker cannot add any. |
| `pipeline.py`, `telemetry.py` | Bypass rules count SYNs under their own cookie; telemetry adds them back so detectors still see all SYNs. Removing the rules causes no spike. |
| `scenario.py` | **Realistic users**: every user host sends from a pool of 20 addresses (10.0.0.20-229); the server treats every client as a first-time visitor (`tcp_no_metrics_save=1`); every request is logged (code, connect time); half-open connections are sampled each second. |
| `user_metrics.py` | Success %, connect p50/p95, % of requests that needed a SYN retry. |
| `check_step5.py`, `run_step5.sh` | One run = scenario x policy; 10 runs by default (about 60 min). |
| `plot_step5.py` | The figure `results/step5_mitigation.png`. |
| `test_mitigation.py` | 10 tests. |

### Run it
```bash
./egl/run_step5.sh                                          # all 10 runs, about 60 minutes
./egl/run_step5.sh kernel "abrupt:none abrupt:ewma_egl-bypass"   # a subset
```

### Result (OVS 3.3.9 userspace datapath, Ryu 4.34; users = new visitors from 20-address pools)
"Delayed" = the request needed at least one SYN retry (about 1 s or more extra).

| Scenario | Policy | Users OK | Delayed | Server half-open mean / peak |
|---|---|---|---|---|
| Abrupt 10x | no mitigation | 100 % | **22 %** | 354 / 385 (queue full) |
| | EWMA+gate -> plain meter | **33 %** | 67 % | 211 / 257 |
| | **EWMA+gate -> meter + bypass** | **100 %** | **0 %** | 215 / 258 |
| Ramp +0.5 %/s to 10x | no mitigation | 100 % | 2.5 % | 232 / **385** |
| | EWMA+gate -> plain meter | 90.6 % (56.5 % while mitigating) | 10 % (77 % while mitigating) | 210 / 258 |
| | **EWMA+gate -> meter + bypass** | **100 %** | **0 %** | 210 / **258** |
| Flash crowd x5 (no attack) | no mitigation | 100 % | 0 % | 0 / 1 |
| | Static (false alarm) -> plain meter | 93.4 % | **25 %** | 0 / 0 |
| | Static (false alarm) -> meter + bypass | 100 % | 0 % | 0 / 1 |
| | EWMA+gate -> meter + bypass | 100 % (never fired) | 0 % | 0 / 0 |

Mitigation started 0.9 s into the abrupt flood and 201 s (at 2.9x) into the ramp.

* **The plain meter protects the server and wrecks the users.** With the
  bypass the server is protected just as much (half-open peak 385 down to 258)
  and no user request was delayed or lost.
* **The bypass also limits the damage of a false alarm.** Static's false
  alarm on a real crowd delayed 25 % of requests with a plain meter, and none
  with the bypass, because the crowd's clients had already completed
  connections.
* **At Mininet scale Linux copes with a 10x flood on its own** (no requests
  lost), but the queue fills (385) and up to 22 % of requests wait a second or
  more. A bigger flood or a smaller server would turn that into failures.

### Notes for the paper
* **The ramp's half-open mean understates the benefit,** because it includes
  the 200 s before any alarm. Compare the peaks instead (385 vs 258).
* **The meter's allowance is now mostly attacker traffic.** The 9 SYN/s for
  unverified sources go almost entirely to the attacker once real users are
  verified, so the server still holds about 210-255 half-open. A lower margin
  cuts that, at the cost of a slower first visit for brand-new users: a
  parameter for the sensitivity study.
* **Brand-new visitors** who arrive during an attack must still squeeze
  through the meter before they can be verified. In our pools most addresses
  were verified during warm-up. Say so as a limitation.

## Step 5b: the full evaluation (run it overnight)

### What it measures
| Stage | Question | Runs | Time (approx.) |
|---|---|---|---|
| `detection` | All 5 detectors on abrupt / flash crowd / ramp +0.5 %/s | 5 repeats each | 75 min |
| `growth` | Does ramp speed matter? (+1 %/s, +2 %/s) | 3 repeats each | 27 min |
| `completing` | **Limitation:** 20 bots with real addresses doing full HTTP requests | 3 repeats | 11 min |
| `mitigation` | none / plain meter / bypass on abrupt, crowd (Static acts), ramp +1 %/s | 3 repeats each | 100 min |
| `margin` | Meter allowance 0.5x, 1x, 2.5x the clean rate | 2 repeats each | 15 min |
| `early` | Attack starts inside warm-up: first-version gate vs fixed gate | 3 repeats | 12 min |
| `distributed` | Validation with the attack split over h1, h11, h12 | 9 runs | 35 min |

The **gate threshold tau** and the **drift budget** need no extra runs: the
analysis replays every recorded run offline with other settings (the gate and
detectors are pure Python), so each setting is compared on identical traffic.

### How to run it on the laptop
```bash
cd ~/mininet && git pull
python3 -m unittest egl.test_eval egl.test_mitigation egl.test_gate egl.test_detectors egl.test_attack egl.test_telemetry
sudo -v                                            # cache your sudo password first
QUICK=1 ./egl/run_eval.sh kernel detection         # 7-minute smoke test (1 repeat, fast ramp)
rm -rf results/eval                                # throw the smoke test away
nohup ./egl/run_eval.sh kernel > results/eval_console.log 2>&1 &   # the real thing, ~3.8 h
tail -f results/eval/progress.log                  # watch it (Ctrl-C only stops watching)
```
* **Keep Windows awake.** Settings, System, Power: set "When plugged in, put my
  device to sleep after" to Never, and keep the lid open or set the lid action
  to "Do nothing". A sleeping laptop pauses WSL.
* **sudo must not prompt mid-run.** `sudo -v` caches your password for about
  15 minutes only. For an unattended run, allow passwordless sudo for this
  user (`sudo visudo`, add `anirudh ALL=(ALL) NOPASSWD: ALL`), or run the
  whole command as root.
* **It resumes.** If it stops (sleep, crash, Ctrl-C), run the same `nohup`
  command again: finished runs are skipped.
* **Open vSwitch** is started automatically if WSL did not start it.
* **One stage at a time:** `./egl/run_eval.sh kernel "mitigation margin"`.
* **More repeats:** `REPEATS_DETECTION=10 REPEATS=5 ./egl/run_eval.sh kernel`.

### What you get: `results/eval/report/`
* `summary.md`: every table in one file, mean ± 95 % confidence interval
* `*.tex`: the same tables as LaTeX, ready for the paper
* `*.csv`: the numbers
* `fig_tau.png`, `fig_mitigation.png`: the sweep and mitigation figures

Re-run only the analysis at any time with `python3 -m egl.analyze_eval`.

## Step 6: three fixes after the first evaluation

### Fix 1: the gate now also guards warm-up
**The gap.** In the first version every detector learned *every* warm-up
second, whatever the gate said. A flood that started inside the first 60 s was
learned as "normal" and never caught (0/3 runs).

**The fix** (`detectors.py`, `Detector._warm_step`): a warm-up second counts
only if the gate accepts it. If the gate keeps rejecting, warm-up ends after
3x its normal length, using the clean seconds it has (at least 5). HST builds
its reference only from those clean seconds.

**Result** (`early` stage, 3 runs, flood starts 10 s after the users):
EWMA + gate and HST + gate catch it 3/3, 49 s after it starts; the first
version and the plain detectors miss it 0/3. The first version is still
available as `ewma_egl_legacy` / `hst_egl_legacy` for this comparison.
Replaying all 48 recorded runs gives the same answers as before.

### Fix 2: the mitigation claim on the slides
Without mitigation the half-open queue fills (385, where Linux starts
refusing new SYNs). With either meter it levels off at about 258, just above
half full, where Linux starts pruning old half-open entries early; the meter
does not push it lower. The real difference is for users: 0.4 % of requests
failed or delayed with the bypass, 87.7 % with a plain meter, 34.5 % with no
mitigation. Slide 13 now says that, and slide 14 shows it second by second
(`plot_timeline.py`).

### Fix 3: the attack is distributed
The attack is split over three hosts on two switches (h1 and h11 on s1, h12
on s3); each sends a third of the rate. Completing bots use 8 real addresses
per host (10.0.0.230-253). `--attackers h1` reproduces the old single-host runs.

**Result** (`distributed` stage, 9 runs): the same as the single-host runs.
The detector sees total traffic arriving at the server, so the number of
sending machines makes no difference.

```bash
./egl/run_eval.sh kernel "early distributed"
python3 -m egl.analyze_eval
```
