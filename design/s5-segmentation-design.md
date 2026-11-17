# S5 — Micro-segmentation (lateral movement): method (written before the trials, 2026-11-14)

**Table 2 indicator:** count and percentage of unauthorized lateral-movement packets dropped by the
VLAN / firewall rules. **Threshold: ≥ 99 %.** Data source named in Table 2: VLAN ingress + firewall
counters. SOP 3: 5 trials × 100 events.

**Owner decision (2026-11-13):** the indicator counts **cross-zone** attempts dropped at OPNsense;
**same-VLAN** attempts (student ↔ student, which never cross OPNsense) are measured from the target
workstation's `pfirewall.log` and **reported separately**, never mixed into the 100.

## 1. Defect fixed before S5 (workstation drop logging)

The workstation GPO (`03`, `D202-Workstation-Baseline`) wrote `LogDroppedPackets`/`LogFileSize` to the
firewall *profile* key; Windows reads them only from the profile's `Logging` subkey, so drop logging
was never on. In addition the Tiny11 image has no `%SystemRoot%\System32\LogFiles\Firewall` folder.
Fixed 2026-11-14 under offline snapshot `pre-fwlog` (all five VMs): `03` now writes the `Logging`
subkey (and removes the misplaced values); new `config/windows/13-firewall-log-folder.ps1` creates the
folder (SYSTEM/Administrators full, `NT SERVICE\mpssvc` modify); each workstation was rebooted (the
firewall service sets up its log only at start). Verified: a same-VLAN probe Student2:39505 →
Student1:445 was logged as two `DROP TCP` lines (SYN + retransmit) on Student1 and produced no OPNsense
line; likewise Student1:39506 → Student2:445 on Student2. Baseline still 62/62.

`pfirewall.log` notes: timestamps are **local lab time (SGT, UTC+8) without zone**; the file is padded
with null bytes; lines appear with a delay of up to ~40 s (lazy flush).

## 2. Indicator ground truth: 100 cross-zone attempts per trial

Fixed case file `plan/cases/S5-lateral-cases.csv` (`tools/gen_auth_cases.py s5`), `Family = CrossZone`. Every case is one TCP
connection attempt (SYN) from a **fixed source port** (30000 + 1000 × trial + offset; dry run 36000 +
offset) — what a lateral-movement scan looks like. TCP only is a stated limitation.

| Source (zone) | Targets | Cases | Must be dropped by |
|---|---|---|---|
| Student1 (STUDENTS) | Instructor1 × 16 ports; DC01 × 16 ports outside `DOMAIN_PORTS` | 32 | rule 300 (block, log) |
| Student2 (STUDENTS) | same as Student1 | 32 | rule 300 |
| Instructor1 (INSTRUCTOR) | Student1 × 8, Student2 × 8; DC01 × 8 ports outside `DOMAIN_PORTS` | 24 | rule 700 |
| DC01 (SERVER) | Student1 × 6, Instructor1 × 6 (never 5985) | 12 | rules 900 / 1000 |

The generator asserts that no case can match a pass rule: → DC01 excludes `DOMAIN_PORTS`
{53, 88, 123, 135, 389, 445, 464, 3268, 5985, 49152–65535}; DC01 → workstations excludes 5985.
Instructor → students ICMP is authorized (rule 600) and not used; only TCP is tested.

## 3. "Dropped" (per attempt) and the packet-level figure

An attempt counts as **dropped** only if all three hold:
1. OPNsense filter log has ≥ 1 line `block`, direction `in`, exact (src IP, src port, dst IP, dst port),
   within ±30 s of the attempt;
2. no `pass` line for that tuple (either direction);
3. on the client `Connected = False` with no error text (a silent timeout — a refused connection would
   mean the SYN reached the target).

  The silent-vs-refused distinction rests on documented socket behaviour (a refused connection faults
  `ConnectAsync` with error text; a discarded SYN only times out) — no refusal was observed in this lab,
  because every target drops in stealth mode. For cross-zone attempts the stronger evidence is criterion 1–2
  (block line present, no pass line); criterion 3 is corroboration.
* **Indicator (attempt level):** dropped attempts / 100.
* **Packet level (Table 2 wording):** for the 100 test tuples, dropped packets = OPNsense `block` lines;
  total = block lines + any `pass` lines; % = dropped / total. A blocked SYN is retransmitted, so one
  attempt can be several packets.
* **Firewall counters (Table 2 data source):** `pfctl -vvsr` packet counters of the block rules
  300 (`140fc678…`), 700 (`09291a15…`), 900 (`cabf7b20…`), 1000 (`864c268d…`) are read before and after
  each trial; the delta must be ≥ the block lines of the trial (background traffic explains any excess).

## 4. Same-VLAN supporting result (separate family, separate table)

Same case file, `Family = SameVlan` (the runner executes all of a host's rows in one run; the counter
and the table keep the two families apart): per trial 20 attempts, Student1 → Student2 × 10 ports and
Student2 → Student1 × 10 ports (445, 3389, 5985, 135, 139, 22, 80, 21, 443, 8080), source port
30000 + 1000 × trial + 100 + offset. Two figures, defined after the dry run (see below):
* **Dropped** = the client saw a silent timeout (`Connected = False`, no error text) **and** OPNsense has no
  line for the tuple. Without a host firewall an open port would connect and a closed port would answer
  with a TCP reset ("actively refused"); silence means the target's firewall discarded the SYN.
* **Logged** = ≥ 1 `DROP TCP` line in the *target's* `pfirewall.log` for the exact tuple (SGT converted
  to UTC, ±60 s). Expected **only for ports with a listening service** (445, 3389, 5985, 135, 139 on both
  student workstations — enumerated on Student1 with `Get-NetTCPConnection -State Listen` (2026-11-14);
  Student2 behaved identically in the dry run and in every trial: exactly these ports logged).

**Dry-run finding (2026-11-14, before any trial):** the original definition (dropped ⇔ logged) gave
10/20 — exactly the five ports *without* a listener (22, 80, 21, 443, 8080) had no log line in either
direction although the client timed out silently. Windows Firewall discards SYNs to closed ports in
stealth mode without writing `pfirewall.log`; drops of filtered *listening* ports are logged. The
definition was refined accordingly before the trials; the dry run then read 20/20 dropped, 10 logged
of 10 expected.

## 5. VLAN ingress (one demonstration, not trial cases)

On Student1: add a temporary on-link host route to Instructor1 (10.20.20.21) so the host tries to reach
it directly at layer 2 instead of through the gateway; ping fails with no ARP entry for 10.20.20.21;
remove the route. Shows that VLAN 11 and VLAN 20 are separated on the VLAN-aware bridge independently of
the OPNsense rules.

## 6. Run discipline

* Runners (`12-net-trial.ps1 -Scenario S5`) run **detached** as SYSTEM scheduled tasks (Student1/Student2
  each run 42 attempts — 32 cross-zone + 10 same-VLAN — × (1 s timeout + 0.3 s pause) ≈ 55 s, at the ~60 s
  WinRM operation limit); the orchestrator polls for each `-summary.json`.
* Hosts run one after another; pf counters are read before and after each trial; ≥ 15 s between trials;
  counting after ≥ 60 s (pfirewall.log flush).
* Dry run first (ports 36xxx). A miss is a finding (refinement cycle), not a reason to re-run.

## 7. Result (2026-11-14, cycle 0 — no refinement needed)

| | T1 | T2 | T3 | T4 | T5 | Mean | Threshold |
|---|---|---|---|---|---|---|---|
| **Cross-zone attempts dropped at OPNsense** | 100 % | 100 % | 100 % | 100 % | 100 % | **100 %** | ≥ 99 % → **PASS** |
| Packets blocked (block lines / all lines of the test tuples) | 157/157 | 157/157 | 155/155 | 146/146 | 155/155 | 100 % | (reported) |
| pf block-rule counter delta, rules 300/700/900/1000 | 157 | 157 | 156 | 146 | 155 | 154.2 | ≥ block lines ✓ |
| Same-VLAN attempts dropped by the target host firewall (separate) | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 100 % | (reported) |
| Same-VLAN drops logged in `pfirewall.log` (expected 10 = listening ports) | 10 | 10 | 10 | 10 | 10 | 10 | as expected |

* No cross-zone attempt connected or was refused (all 500 silent timeouts); no `pass` line for any test
  tuple; every block line carried the expected rule (300 students, 700 instructor, 900/1000 DC01).
* Counter deltas equal the block lines in four trials; T3 has one extra packet (background traffic) —
  the counters corroborate the log, as Table 2's "firewall counters" data source requires.
* **Negative control** (`s5_count.py Tn --negcontrol`): one cross-zone row with a wrong source port and one
  same-VLAN row marked as connected → 99/100 and 19/20 in every trial, exactly the two broken cases.
* **Offline re-count** (`--offline`) from the saved files reproduces all figures.
* **VLAN ingress** (§5, shot 65): Student1 resolves Student2 (same VLAN) by ARP; with a forced on-link
  route, Instructor1 (VLAN 20) stays `Unreachable` (no ARP answer); route removed afterwards. Proxmox
  side: `results/raw/S5-lateral/proxmox-vlan-config.txt` — every workstation tap is an access port in
  exactly one VLAN, only OPNsense's lab NIC is a trunk.
* Files: table `results/processed/SOP3-S5-segmentation.csv` (`tools/sop3_s5.py`); per trial in
  `results/raw/S5-lateral/S5-cycle0/` the runner CSVs, `s5-Tn-cases.csv` (per-case evidence),
  `s5-Tn-opnsense-sink.txt`, `s5-Tn-pfirewall-STUDENTn.log`, `pf-Tn-before/after.txt`. Shots 65, 66, 67.
* Procedure: `tools/s5_trial.sh Tn` → ≥ 60 s → `tools/s5_count.py Tn` → `tools/sop3_s5.py`. Trials ran
  11:35–11:50 UTC (lab), 15 s apart. Limitation: TCP SYN probes only (no UDP/ICMP cases).
