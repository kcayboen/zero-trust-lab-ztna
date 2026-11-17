# D202 ZTNA policy matrix — frozen for the Table 2 trials

**Policy version:** `D202-ZTNA-1.1` (frozen 2026-11-14, lab date). Machine-readable twin: `policy-matrix.csv`.
**Approved by the project owner:** option "Match the PEP"; the three consistency corrections in §3
(instructor auth ports to DC01, no admin RDP from workstations, admin → workstations only from DC01 on 5985)
were explicitly confirmed by the owner on 2026-11-14 — the PDP may be stricter than the
network, but must never allow a request that the PEP (OPNsense + host firewall) blocks.
The RBAC enforcement accuracy indicator is scored against **this table**, through a fixed case
file generated from it (`cases/S2-rbac-cases.csv`), never against the PDP's own output.

## 1. Source statements in the manuscript

* Students may log on to any designated student workstation (so a student can move when a unit is
  unavailable) but not to instructor workstations or the server.
* Instructor accounts get privileges consistent with teaching and administration.
* Server, student and instructor zones are isolated (VLANs + default-deny firewall rules) to prevent
  lateral movement.
* Least privilege; everything not explicitly allowed is denied.

The port-level detail below is this project's instantiation of those statements, derived from the
enforcement actually built (OPNsense rule set in `config/opnsense/03-firewall-rules.md` §0 and the
GPO-only host firewall: inbound only from DC01 and the management host).

## 2. Policy inputs

**(a) Role ← account** (AD groups, `config/windows/02-ous-users-groups.ps1`)

| Role | Accounts | Group |
|---|---|---|
| Student | student01–student10 (probe-ztna01 is a Student used only for lockout tests) | GG-Students |
| Instructor | instructor01–instructor03 | GG-Instructors |
| ZTNA-Admin | admin-ztna01 | GG-ZTNA-Admins |
| *(none)* | svc-ztna-pdp, any unknown account | → always Deny |

**(b) Devices / resources and their zone**

| Name | Zone | Address |
|---|---|---|
| Student1, Student2 | StudentWS (VLAN 11) | 10.20.11.21, .22 |
| Instructor1 | InstructorWS (VLAN 20) | 10.20.20.21 |
| DC01 | Server (VLAN 30) | 10.20.30.10 |

**(c) Where a role may sit (interactive logon, GPO logon rights)**

| Role | Permitted device zones |
|---|---|
| Student | StudentWS |
| Instructor | StudentWS, InstructorWS |
| ZTNA-Admin | StudentWS, InstructorWS, Server |

A request from a device zone not listed for the role is denied (`DENY_DEVICE_ROLE_MISMATCH`).

**(d) Global deny ports:** 21, 23, 25, 69, 111, 1433, 3306, 5432 — never allowed.

**(e) Access matrix** (request = user at *device* → *resource* : *port*). *Target* is `Local` when
the resource **is** the device the user sits at, otherwise the resource's zone.

| Role | From device zone | Target | Allowed ports | Why |
|---|---|---|---|---|
| Student | any permitted | Local | 445, 139 | own workstation's local resources |
| Student | any permitted | Server | 53, 88, 389 | authentication services only (DNS, Kerberos, LDAP) |
| Instructor | any permitted | Local | 445, 139, 3389 | own (or currently used) workstation |
| Instructor | any permitted | Server | 53, 88, 389 | authentication services only |
| ZTNA-Admin | any permitted | Local | 445, 3389, 5985 | administration of the device in use |
| ZTNA-Admin | StudentWS | Server | 53, 88, 389, 445, 5985 | OPNsense `DOMAIN_PORTS` (no RDP 3389 from workstation zones) |
| ZTNA-Admin | InstructorWS | Server | 53, 88, 389, 445, 5985 | same |
| ZTNA-Admin | Server | StudentWS | 5985 | OPNsense LAN rule 850 (WinRM only) |
| ZTNA-Admin | Server | InstructorWS | 5985 | OPNsense LAN rule 860 |

**(f) Default deny:** every combination not in (e) is denied, in particular
* any role → a **peer** workstation in the same zone (student↔student lateral movement),
* Student/Instructor at a student workstation → Instructor1 (OPNsense STUDENTS default deny),
* Instructor at Instructor1 → student workstations (OPNsense allows ICMP only),
* Student/Instructor → Server on any port other than 53/88/389.

## 3. Changes from D202-ZTNA-1.0 (documented policy change)

| 1.0 | 1.1 | Reason |
|---|---|---|
| Student → StudentWS 445/139 (any student workstation) | Local only; peer workstation denied | PEP blocks student↔student; lateral movement |
| Instructor → StudentWS 445/139/3389 | Local only (instructor may *sit* at a student WS) | PEP blocks INSTRUCTOR → STUDENTS except ICMP |
| Instructor → Server: none | 53/88/389 | PEP passes domain ports; instructors must authenticate |
| ZTNA-Admin → Server 3389 | removed (from workstations) | `DOMAIN_PORTS` has no 3389 |
| ZTNA-Admin → StudentWS/InstructorWS 445/3389/5985 from anywhere | 5985 from Server only | LAN rules 850/860; INSTRUCTOR/STUDENTS cannot reach each other |

The PDP remains stricter than the PEP where the network must carry domain infrastructure traffic
(e.g. the PEP passes 135/445/464/3268/5985/dynamic RPC from workstations to DC01 for Group Policy,
Kerberos password change and WEF, while a Student *user* request to DC01:445 is denied).
