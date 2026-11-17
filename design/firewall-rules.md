# 03 — Firewall rules, aliases and NAT (the PEP policy)

**Target:** OPNsense CE 26.7 · **Docs:** <https://docs.opnsense.org/manual/firewall.html>,
<https://docs.opnsense.org/manual/aliases.html>, <https://docs.opnsense.org/manual/firewall_settings.html>

---

## 0. AS BUILT — rules live on the appliance (2026-11-13)

The design rule set in §1 onward has **not** been applied. The appliance runs the original lab
rule set (cloned from VM 104) plus the two device-validation gates added in the DHCP step
(`02-dhcp-reservations.md` §3). Live user rules, in evaluation order per interface:

| Seq | Interface | Action | Source → Destination : Port | Log | Description |
|---|---|---|---|---|---|
| **50** | STUDENTS | **block** | **NOT `KNOWN_MACS`** → any | yes | `ZTNA-Student-Deny-Unregistered-MAC` |
| 100 | STUDENTS | pass | STUDENT_NETS → STUDENTS address, ICMP | no | ping gateway |
| 200 | STUDENTS | pass | STUDENT_NETS → SRV_WIN : DOMAIN_PORTS (TCP/UDP) | **yes** (since 2026-11-14, S6) | Domain Services |
| 250 | STUDENTS | pass | STUDENTS net → 10.20.30.10, ICMP | yes | students ICMP to DC01 |
| 260 | STUDENTS | pass | STUDENTS net → 10.20.11.1:53 | yes | students DNS to OPNsense |
| 300 | STUDENTS | block | STUDENT_NETS → any | yes | Default deny |
| **350** | INSTRUCTOR | **block** | **NOT `KNOWN_MACS`** → any | yes | `ZTNA-Instructor-Deny-Unregistered-MAC` |
| 400 | INSTRUCTOR | pass | INSTRUCTOR net → INSTRUCTOR address, ICMP | no | ping gateway |
| 500 | INSTRUCTOR | pass | INSTRUCTOR net → SRV_WIN : DOMAIN_PORTS | **yes** (since 2026-11-14, S6) | Domain services |
| 550 | INSTRUCTOR | pass | INSTRUCTOR net → 10.20.30.10, ICMP | yes | instructor ICMP to DC01 |
| 560 | INSTRUCTOR | pass | INSTRUCTOR net → 10.20.20.1:53 | yes | instructor DNS to OPNsense |
| 600 | INSTRUCTOR | pass | INSTRUCTOR net → STUDENT_NETS, ICMP | no | ping students |
| 700 | INSTRUCTOR | block | INSTRUCTOR net → any | yes | Default deny |
| 800 | LAN | pass | LAN net → LAN address, ICMP | no | ping gateway |
| 850 | LAN | pass | LAN net → STUDENTS net :5985 | yes | DC01 policy pull to students (WinRM) |
| 860 | LAN | pass | LAN net → INSTRUCTOR net :5985 | yes | DC01 policy pull to instructor |
| 900 | LAN | block | LAN net → STUDENT_NETS | yes | Server cannot start to students |
| 1000 | LAN | block | LAN net → INSTRUCTOR net | yes | Server cannot start to instructor |
| 1100 | LAN | pass | LAN net → any | no | server to internet |
| 1200 | WAN | pass | MGMT_HOSTS (192.168.8.242, .250) → any (`disablereplyto=1`) | yes | management |

Logging on 200/500 was turned on by owner decision for S6 (granted cross-zone access to DC01 must be an
OPNsense event); snapshot `pre-s6-logging` (VM 202), backup `backup/config-pre-s6-logging-2026-11-14.xml`.
`DOMAIN_PORTS` = 53, 88, 123, 135, 389, 445, 464, 3268, 5985, 49152–65535. Automatic Dnsmasq DHCP
rules precede all of the above. Reconciling this with the design below is part of the
segmentation step.

---

## 1. Evaluation model (read before writing any rule)

From the OPNsense 26.7 firewall documentation:

* Rules are evaluated **Floating → [Interface] Groups → Interface rules**; within a section the
  **first matching rule wins** (`quick` = 1, the default).
* The **implicit default is block**: *"since we match traffic on `inbound`, make sure to add rules
  where traffic originates from … the default (inbound) policy is `block` if nothing else is
  specified."*
* Rules are **stateful by default**: the return direction of an allowed flow is permitted
  automatically (this is how the design's *"established/related allowed"* requirement is satisfied).
* Automatic/system rules (anti-lockout, bogon/private-network blocks, NAT helpers) are registered
  **before** user rules and therefore win over them.

**Consequences for this design**

1. Every policy below is placed on the interface **where the traffic enters** (the "in" direction),
   i.e. on the zone interface of the *source* zone.
2. All blocking rules are **explicit** (not left to the implicit default) so that every denial is a
   named, greppable, logged event — this is the micro-segmentation evidence for Table 2.
3. Rule **descriptions begin with `ZTNA-`**. Since OPNsense 26.7.3 the pf rule label is persistent
   across reloads ("*firewall: use new 'rlabel' from pfctl for persistent rule identification across
   reloads*"), so the label appears verbatim in `filter.log` and in the remote syslog stream —
   which is what makes the five-trial metrics computable.

### 1.1 Interface identifiers used below

`STUDENT`, `INSTRUCTOR`, `SERVER`, `MGMT`, `WAN` are **symbolic names**. Substitute the real
identifiers (`opt1`…`opt4`) recorded in `01-interfaces.md` §1.2. Rules reference interfaces only
through the interface tab, so a wrong mapping is immediately visible in
`Firewall → Rules → <tab>`.

### 1.2 How to add a rule (identical for every row)

`Firewall → Rules` → select the **interface tab** (e.g. *STUDENT*) → `+` (Add) → fill the form:

| Form field | Value |
|---|---|
| Action | `Pass` / `Block` (see tables) |
| Quick | ✔ (default) |
| Interface | the tab's interface (auto-filled) |
| Direction | `in` |
| Protocol | `TCP`, `UDP`, `TCP/UDP`, `ICMP`, `any` |
| Source | alias or address (see tables) — for a negation tick the **Not** box next to the field |
| Source Port | value or alias (see tables) |
| Destination | alias or address; `This Firewall (self)` may be used for the interface's own address |
| Destination Port | value or alias |
| **Log** | ✔ for every rule (grants = “Audit”) |
| Description | `ZTNA-…` exactly as written in the tables |
| Categories | the zone category (see §3) |
| Sequence | as given in the tables (lower = earlier) |
| Advanced → *State type* | `keep state` (default) — leave as-is |

`Save` → **Apply changes** at the top of the page (rules only take effect after Apply).

---

## 2. Aliases

**Menu:** `Firewall → Aliases` → `+` → *Type* + *Content* → `Save` → **Apply changes**.
**Docs:** <https://docs.opnsense.org/manual/aliases.html> (alias types include *Host(s)*,
*Network(s)*, *Port(s)*, **MAC address**, *Network group*).

| Alias name | Type | Content | Purpose |
|---|---|---|---|
| `STUDENT_NET` | Network(s) | `10.20.11.0/24` | student zone |
| `INSTRUCTOR_NET` | Network(s) | `10.20.20.0/24` | instructor zone |
| `SERVER_NET` | Network(s) | `10.20.30.0/24` | server zone |
| `MGMT_NET` | Network(s) | `10.20.12.0/24` | management zone |
| `ZTNA_ZONE_NETWORKS` | Network group | `STUDENT_NET`, `INSTRUCTOR_NET`, `SERVER_NET`, `MGMT_NET` | all zones as one object (used by the laptop-management rules) |
| `DC01` | Host(s) | `10.20.30.10` | domain controller / AD DNS |
| `SMB_SHARE` | Host(s) | `10.20.30.11` | SMB file-share host — **placeholder, confirm** (see Open item O-2) |
| `KNOWN_MACS` | MAC address | `BC:24:11:AA:00:01`, `BC:24:11:AA:00:06`, `BC:24:11:AA:00:04` | registered devices (device validation) |
| `THESIS_LAPTOP` | Host(s) | `192.168.8.250` | thesis laptop (test automation origin) |
| `HOST_NET` | Network(s) | `192.168.8.0/24` | Proxmox/host network (WAN side) |
| `ZTNA_DC_PORTS` | Port(s) | `53,88,389,636,445,123` | the DC01 service set (documentation / optional bulk rule) |

> ⚠ **Open item O-2:** the design says *"Instructors → DC01 services + SMB file share"* but does not
> give the share's address. This package assumes a second server at **10.20.30.11** (alias `SMB_SHARE`).
> If the share lives on DC01 itself, set `SMB_SHARE` = `10.20.30.10` and the rule set still holds.
> Confirm before the trials and update the alias in one place.

**Alias hygiene**

* Alias **names** are case-sensitive-ish and must be unique; use upper case as above.
* MAC aliases resolve to IP addresses via Hostwatch/ARP and refresh on the *Aliases Resolve Interval*
  (default 300 s). Force a refresh with `configctl filter refresh_aliases`.
* Inspect resolved content: **Firewall → Diagnostics → Aliases** (or `pfctl -t KNOWN_MACS -T show`).

---

## 3. Categories (audit grouping, 26.7 feature)

**Menu:** `Firewall → Categories` → `+` → Name (+ optional colour).

| Category | Purpose |
|---|---|
| `ZTNA-Student` | student-zone policy |
| `ZTNA-Instructor` | instructor-zone policy |
| `ZTNA-Server` | server-zone policy |
| `ZTNA-Management` | management plane / laptop access |
| `ZTNA-DefaultDeny` | explicit default-deny rules |

Categories let the firewall grid be filtered to one zone (evidence for Appendix C) and are carried
in the rule record.

---

## 4. Rule set — evaluation order

Legend: **Seq** = Sequence field · **Log** = Log/Audit enabled (all rows: ✔).

### 4.1 Interface `STUDENT` (vlan11) — source zone for students

| # | Seq | Description | Source | Source port | Destination | Dest port | Proto | Action | Log | Rationale (ZTNA least privilege) |
|---|---|---|---|---|---|---|---|---|---|---|
| S-01 | 1000 | `ZTNA-Student-Allow-DHCP` | `STUDENT_NET` | 67–68 | `10.20.11.1` (This Firewall) | 67–68 | UDP | Pass | ✔ | Kea must be able to answer the lease request. *If Kea's "Firewall rules" option is ON this rule is created automatically — keep either, not both.* |
| S-02 | 1010 | `ZTNA-Student-Deny-Unregistered-MAC` | `KNOWN_MACS` **+ Not** | any | any | any | any | **Block** | ✔ | **Device validation (Zero Trust: verify the device before authorizing).** Any traffic from a MAC that is not registered is dropped and logged. Must be enabled only after `KNOWN_MACS` resolves to content. |
| S-03 | 1020 | `ZTNA-Student-Deny-Firewall-Management` | `STUDENT_NET` | any | `10.20.11.1` (This Firewall) | any | any | **Block** | ✔ | No student access to the OPNsense GUI/SSH on the zone gateway. Placed after S-01 so DHCP still works. Requires the anti-lockout rule to be disabled (§7) for this rule to be effective. |
| S-04 | 1030 | `ZTNA-Student-Allow-DNS-to-DC01` | `STUDENT_NET` | any | `DC01` | 53 | UDP/TCP | Pass | ✔ | Domain join, Kerberos service discovery, GPO resolution. DNS is the root dependency of AD authentication. |
| S-05 | 1040 | `ZTNA-Student-Allow-Kerberos-to-DC01` | `STUDENT_NET` | any | `DC01` | 88 | UDP/TCP | Pass | ✔ | AD authentication (KDC). Directly supports the *authentication latency ≤ 300 ms* indicator. |
| S-06 | 1050 | `ZTNA-Student-Allow-LDAP-to-DC01` | `STUDENT_NET` | any | `DC01` | 389, 636 | TCP | Pass | ✔ | Group Policy / validation / RBAC lookups. |
| S-07 | 1060 | `ZTNA-Student-Allow-SMB-to-DC01` | `STUDENT_NET` | any | `DC01` | 445 | TCP | Pass | ✔ | Domain logon (NTLM), sysvol/GPO retrieval. |
| S-08 | 1070 | `ZTNA-Student-Allow-NTP-to-DC01` | `STUDENT_NET` | any | `DC01` | 123 | UDP | Pass | ✔ | Time sync; Kerberos tolerance is 5 min, so this prevents auth failures that would corrupt the latency metric. |
| S-09 | 1080 | `ZTNA-Student-Allow-WinRM-to-DC01-from-Laptop` | `THESIS_LAPTOP` | any | `DC01` | 5985 | TCP | Pass | ✔ | **Test automation only.** The design limits WinRM from students to 192.168.8.250; the source is pinned to that host so a student workstation can never use WinRM. Add 5986 only if DC01 actually runs an HTTPS WinRM listener (verify: `winrm enumerate` on DC01). |
| S-10 | 1090 | `ZTNA-Student-Allow-WAN-HTTP-Update` | `STUDENT_NET` | any | any (→ WAN) | 80, 443 | TCP | Pass | ✔ | Only web traffic may leave the student zone (OS/AV updates). Set **Gateway** = the WAN gateway so the flow is routed out of `vtnet0` and matched by the Source NAT rule `N-01`. |
| S-11 | 1100 | `ZTNA-Student-Deny-Instructor-Zone` | `STUDENT_NET` | any | `INSTRUCTOR_NET` | any | any | **Block** | ✔ | **Explicit deny + log** of student → instructor lateral movement (primary micro-segmentation evidence). |
| S-12 | 1110 | `ZTNA-Student-Deny-Server-Zone` | `STUDENT_NET` | any | `SERVER_NET` | any | any | **Block** | ✔ | Deny to *all* server hosts. S-04…S-08 already allowed only the named DC01 services, so this closes every other port/host on the server zone. |
| S-13 | 1120 | `ZTNA-Student-Deny-Mgmt-Zone` | `STUDENT_NET` | any | `MGMT_NET` | any | any | **Block** | ✔ | Management plane isolation. |
| S-14 | 1130 | `ZTNA-Student-Default-Deny` | `STUDENT_NET` | any | any | any | any | **Block** | ✔ | **Explicit, logged default deny.** Makes the zone's implicit deny visible, countable and auditable instead of relying on an unnamed automatic rule. |

### 4.2 Interface `INSTRUCTOR` (vlan20)

| # | Seq | Description | Source | Destination | Dest port | Proto | Action | Log | Rationale |
|---|---|---|---|---|---|---|---|---|---|
| I-01 | 2000 | `ZTNA-Instructor-Allow-DHCP` | `INSTRUCTOR_NET` | `10.20.20.1` | 67–68 | UDP | Pass | ✔ | Lease for Instructor1 (auto-created if Kea "Firewall rules" is ON). |
| I-02 | 2010 | `ZTNA-Instructor-Deny-Unregistered-MAC` | `KNOWN_MACS` **+ Not** | any | any | any | **Block** | ✔ | Device validation for the instructor zone. |
| I-03 | 2020 | `ZTNA-Instructor-Deny-Firewall-Management` | `INSTRUCTOR_NET` | `10.20.20.1` | any | any | **Block** | ✔ | No zone access to the firewall services. |
| I-04 | 2030 | `ZTNA-Instructor-Allow-DC01-Services` | `INSTRUCTOR_NET` | `DC01` | 53, 88, 389, 636, 445, 123 | UDP/TCP | Pass | ✔ | Instructors receive the full DC01 service set (DNS, Kerberos, LDAP, SMB, NTP). One rule with the `ZTNA_DC_PORTS` alias; split per service if the panel wants per-service counters. |
| I-05 | 2040 | `ZTNA-Instructor-Allow-SMB-FileShare` | `INSTRUCTOR_NET` | `SMB_SHARE` | 445 | TCP | Pass | ✔ | The instructor's legitimate file-share path (least privilege: SMB to one host only). |
| I-06 | 2050 | `ZTNA-Instructor-Allow-WAN-HTTP-Update` | `INSTRUCTOR_NET` | any (→ WAN) | 80, 443 | TCP | Pass | ✔ | Web egress for updates; matches Source NAT `N-02`. |
| I-07 | 2060 | `ZTNA-Instructor-Deny-Student-Admin` | `INSTRUCTOR_NET` | `STUDENT_NET` | 22, 135, 445, 3389, 5985, 5986 | TCP | **Block** | ✔ | **"No student-workstation admin"**: an instructor may not RDP/WinRM/SMB/SSH into student workstations, preventing role escalation into the student segment. |
| I-08 | 2070 | `ZTNA-Instructor-Deny-Server-Zone` | `INSTRUCTOR_NET` | `SERVER_NET` | any | any | **Block** | ✔ | After I-04/I-05: no other server host or port is reachable. |
| I-09 | 2080 | `ZTNA-Instructor-Deny-Mgmt-Zone` | `INSTRUCTOR_NET` | `MGMT_NET` | any | any | **Block** | ✔ | Management plane isolation. |
| I-10 | 2090 | `ZTNA-Instructor-Default-Deny` | `INSTRUCTOR_NET` | any | any | any | **Block** | ✔ | Explicit logged default deny. |

### 4.3 Interface `SERVER` (vlan30)

| # | Seq | Description | Source | Destination | Dest port | Proto | Action | Log | Rationale |
|---|---|---|---|---|---|---|---|---|---|
| V-01 | 3000 | `ZTNA-Server-Allow-DC01-Management-RPC` | `DC01` | `STUDENT_NET`, `INSTRUCTOR_NET` | 135, 445, 5985, 5986, 49152–65535 | TCP | Pass | ✔ | **"DC01 → workstation VLANs for management only (RPC/WinRM)".** 135 + the dynamic RPC range are the Windows RPC ports; 445 for remote registry/policy; 5985/5986 for WinRM. Return traffic is permitted automatically (stateful = established/related). |
| V-02 | 3010 | `ZTNA-Server-Allow-WAN-HTTP-Update` | `SERVER_NET` | any (→ WAN) | 80, 443 | TCP | Pass | ✔ | Server zone → WAN updates; matches Source NAT `N-03`. Windows Update / Defender definition updates. |
| V-03 | 3020 | `ZTNA-Server-Deny-Student-VLAN` | `STUDENT_NET` | `SERVER_NET` | any | any | **Block** | ✔ | Defence in depth: the same student→server denial is also enforced at the server side, so a mis-scoped student rule cannot expose a server. |
| V-04 | 3030 | `ZTNA-Server-Deny-Instructor-VLAN` | `INSTRUCTOR_NET` | `SERVER_NET` | any | any | **Block** | ✔ | Same defence in depth for the instructor zone (after V-01). |
| V-05 | 3040 | `ZTNA-Server-Deny-Mgmt-Zone` | any | `MGMT_NET` | any | any | **Block** | ✔ | No server may reach the management zone. |
| V-06 | 3050 | `ZTNA-Server-Default-Deny` | `SERVER_NET` | any | any | any | **Block** | ✔ | Explicit logged default deny for the server zone. |

> **Note on V-01 vs V-03/V-04:** V-01 is *earlier* (lower sequence) and source-specific
> (`DC01`), so DC01's management traffic is allowed while workstation-initiated traffic to the
> server zone is denied. Ordering is the whole mechanism — do not reorder.

### 4.4 Interface `MGMT` (vlan12)

| # | Seq | Description | Source | Destination | Dest port | Proto | Action | Log | Rationale |
|---|---|---|---|---|---|---|---|---|---|
| M-01 | 4000 | `ZTNA-Mgmt-Default-Deny` | `MGMT_NET` | any | any | any | **Block** | ✔ | The management zone carries no user or server traffic; the administrative path is the laptop on the host network (§4.5). Every packet on it is a policy violation and is logged as such. |

### 4.5 Interface `WAN` (vtnet0)

| # | Seq | Description | Source | Destination | Dest port | Proto | Action | Log | Rationale |
|---|---|---|---|---|---|---|---|---|---|
| W-01 | 5000 | `ZTNA-Mgmt-Laptop-WinRM-All-Zones` | `THESIS_LAPTOP` (192.168.8.250) | `ZTNA_ZONE_NETWORKS` | 5985, 5986 | TCP | Pass | ✔ | **Test automation:** the thesis laptop drives the Windows VMs over WinRM from outside every zone. Source-pinned to one host. |
| W-02 | 5010 | `ZTNA-Mgmt-Laptop-ICMP-All-Zones` | `THESIS_LAPTOP` | `ZTNA_ZONE_NETWORKS` | — | ICMP (echo) | Pass | ✔ | Reachability/health checks used by `06-verify.sh`. |
| W-03 | 5020 | `ZTNA-Mgmt-Laptop-DNS-to-DC01` | `THESIS_LAPTOP` | `DC01` | 53 | UDP/TCP | Pass | ✔ | Lets the laptop resolve `student1.internal.lab` etc. for WinRM targeting (optional; keep if the automation resolves names). |
| W-04 | 5030 | `ZTNA-Admin-Laptop-Firewall-GUI-SSH` | `THESIS_LAPTOP` | WAN address (This Firewall) | 443, 22 | TCP | Pass | ✔ | Explicit administrative access for the thesis operator, replacing the anti-lockout rule (§7). |
| W-05 | 5040 | `ZTNA-WAN-Default-Deny` | any | any | any | any | **Block** | ✔ | Explicit logged default deny on the WAN edge (in addition to OPNsense's implicit WAN deny). |

> **NAT is required for the three egress rules.** S-10, I-06 and V-02 leave via the WAN gateway; the
> matching Source NAT rules are in §5. Without them the flows fail with "no NAT" and the trials
> record the wrong result.
>
> **Anti-lockout and the WAN tab:** OPNsense's anti-lockout rule protects GUI access from the
> *LAN-type* interfaces; it does not open the WAN. The WAN remains deny-by-default, which is why
> W-01…W-04 are needed for the laptop.

---

## 5. Source NAT (outbound)

**Menu (26.7):** `Firewall → NAT → Source NAT` → `+`.
*(The legacy "Outbound" page moved to the `os-firewall-legacy` plugin in 26.7.5; the MVC page is
the one above.)*
**Mode:** `Firewall → NAT → Source NAT → Settings → Mode = Advanced (manual source NAT rule
generation)` — with *hybrid* mode OPNsense generates hidden NAT rules that make the egress
evidence non-reproducible.

| # | Seq | Description | Interface | Source | Destination | Translation | Filter rule association | Log |
|---|---|---|---|---|---|---|---|---|
| N-01 | 100 | `ZTNA-NAT-Student-Outbound` | WAN | `STUDENT_NET` | any | `WAN` address | `ZTNA-Student-Allow-WAN-HTTP-Update` | ✔ |
| N-02 | 110 | `ZTNA-NAT-Instructor-Outbound` | WAN | `INSTRUCTOR_NET` | any | `WAN` address | `ZTNA-Instructor-Allow-WAN-HTTP-Update` | ✔ |
| N-03 | 120 | `ZTNA-NAT-Server-Outbound` | WAN | `SERVER_NET` | any | `WAN` address | `ZTNA-Server-Allow-WAN-HTTP-Update` | ✔ |

*Filter rule association* binds the NAT rule to its pass rule, so the NAT is only applied to the
permitted flow (never to the denied flows).

**Verify:**

```sh
pfctl -s nat | grep -i ztna          # three nat rules with the ZTNA- labels
pfctl -sn | head -30
```

---

## 6. Global logging switches for the firewall

**Menu:** `Firewall → Settings → Advanced` → section **Logging**.
(Model: `OPNsense.Firewall.Filter.xml`, `<logging>` — `default_block` (default 1), `default_pass`
(default 1), `source_nat`, `bogons`, `private_networks`, `debug`.)

| Option | Value | Why |
|---|---|---|
| Log packets matching (default block) | **on** | logs the implicit default deny as well as the explicit blocks |
| Log packets matching (default pass) | on | gives the "passed" half of the blocked-vs-passed metric |
| Log NAT (source NAT) | on | proves translation happened for the permitted egress |
| Log bogon / private network blocks | off | noise reduction; the WAN uses RFC1918 space by design |
| Debug level | `urgent` (default) | avoids per-packet debug noise in the 100-event trials |

---

## 7. Anti-lockout: how to get a true default-deny

OPNsense adds an automatic rule that always permits web-GUI/SSH access to the firewall from the
LAN-type interfaces, *regardless of user rules*. That would leave every zone able to reach the
firewall's own services, contradicting the default-deny requirement.

**Ordered procedure (do not reorder; keep a console/serial fallback available):**

1. Add rules **W-04** (and **W-02** if wanted) first — they open the GUI/SSH path for
   `192.168.8.250` on the WAN interface.
2. Verify from the laptop: `curl -k https://<WAN-IP>/` and `ssh -p 22 root@<WAN-IP>`.
3. Only then tick **Firewall → Settings → Advanced → Disable anti-lockout**.
4. Apply, then re-verify GUI/SSH from the laptop and re-test the zones: S-03 / I-03 now become
   effective and no zone host can reach `10.20.x.1:443`.
5. If the GUI becomes unreachable: Proxmox → OPNsense VM → **Console** → console menu → option to
   reset the interface / re-enable the anti-lockout rule, or upload the pre-change `config.xml`.

> If the panel prefers not to disable the anti-lockout rule, keep it enabled and **delete**
> S-03/I-03 (they would be dead policy) — and record in Chapter 2 that the firewall's own
> management plane remains reachable from the zones. Do not leave a rule in place that can never
> match; that would corrupt the "denied" counts.

---

## 8. Verification

**On the appliance (read-only):**

```sh
pfctl -s rules | grep -c 'ZTNA-'                 # rule count (expect 14+10+6+1+5 = 36)
pfctl -s rules | grep 'ZTNA-'                   # full rule list with labels
pfctl -vvsr | grep -A1 'ZTNA-'                  # per-rule packet/byte counters (trial metric source)
pfctl -si                                     # PktIn / Pass / Block / Drop totals
pfctl -t KNOWN_MACS -T show                    # device-validation alias contents
grep -c 'ZTNA-' /var/log/filter/filter.log     # locally logged ZTNA events
```

**Behavioural checks (from the student VM):**

```sh
# allowed
nslookup student1.internal.lab 10.20.30.10         # S-04
nc -z -w3 10.20.30.10 88                      # S-05
nc -z -w3 10.20.30.10 445                     # S-07
# must fail (and must appear in the log)
nc -z -w3 10.20.20.21 445                     # S-11  (instructor zone)
nc -z -w3 10.20.30.11 445                     # S-12  (other server host)
nc -z -w3 10.20.12.10 445                     # S-13  (mgmt zone)
```

**Counting proof for the table (blocked vs passed):**

```sh
# on the collector (see 04-syslog.md for paths)
grep 'ZTNA-' filterlog.log | awk -F, '$7=="block"' | wc -l    # blocked
grep 'ZTNA-' filterlog.log | awk -F, '$7=="pass"'  | wc -l    # passed
```

---

## 9. Rule rollback

* Single rule: `Firewall → Rules` → select the rule → *Disable* → Apply (seconds, no restart).
* Whole policy: restore the pre-change `config.xml` (System → Configuration → Backups → Restore)
  or activate the `pre-ztna-*` snapshot (System → Snapshots).
* Never hand-edit `/tmp/rules.debug` — it is regenerated on every reload and is not a supported
  rollback mechanism.

---

## 10. Appendix C screenshot checklist (firewall)

| # | Screen | Content |
|---|---|---|
| F-1 | Firewall → Aliases | all 11 aliases with types (host/network/port/MAC/group) |
| F-2 | Firewall → Categories | the five ZTNA categories |
| F-3 | Firewall → Rules → STUDENT | the 14 ordered rules, `ZTNA-` descriptions, Log column |
| F-4 | Firewall → Rules → INSTRUCTOR | the 10 ordered rules |
| F-5 | Firewall → Rules → SERVER | the 6 ordered rules |
| F-6 | Firewall → Rules → MGMT / WAN | 1 and 5 rules |
| F-7 | Firewall → Rules → *Inspect* toggle | the automatic rules (anti-lockout, bogon) next to the user rules — proof that ordering is understood |
| F-8 | Firewall → NAT → Source NAT | N-01..N-03 with filter-rule associations |
| F-9 | Firewall → Settings → Advanced → Logging | the logging switches of §6 |
| F-10 | Terminal `pfctl -vvsr \| grep -A1 ZTNA-` | per-rule counters (micro-segmentation drop evidence) |
