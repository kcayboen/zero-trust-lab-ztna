#!/usr/bin/env python3
"""Build docs/evaluation.html: the evaluator review page for the Post-Simulation Readiness Evaluation.

Figure labels, titles and notes come from the manuscript's Appendix H list (edit_latest.py, FIGS), so the page and
the thesis use the same numbering. Usage: build_evaluation.py <path-to-edit_latest.py> <out.html>
"""
import ast, html, sys

src = open(sys.argv[1]).read()
i = src.index('FIGS = [')
j = src.index('\n]\n', i) + 2
FIGS = {f[0]: f for f in ast.literal_eval(src[i + 7:j]) if f[1]}

E = html.escape


def fig(label):
    lab, title, fname, note = FIGS[label]
    return (f'<figure><a href="assets/shots/{fname}" target="_blank" rel="noopener"><img loading="lazy" src="assets/shots/{fname}" '
            f'alt="{E(title)}"></a><figcaption><b>Figure {lab}. {E(title)}</b><span>{E(note)}</span></figcaption></figure>')


def figs(*labels):
    return '<div class="figs">' + ''.join(fig(l) for l in labels) + '</div>'


def items(*codes):
    return '<p class="items">Helps with items: ' + ' '.join(f'<span>{c}</span>' for c in codes) + '</p>'


DEMOS = [
    ('A', 'A student is refused at the instructor workstation',
     'In the live session, student01 signs in at Instructor1 with the correct password. The sign-in is refused because students do '
     'not hold the logon right on instructor workstations; the refusal is forwarded to the domain controller as event 4625.',
     ['H16', 'H17']),
    ('B', 'Repeated wrong passwords lock the account',
     'Five wrong passwords for the synthetic test account lock it; even the correct password is then refused. The domain controller '
     'records the lockout (event 4740), and the PDP returns DENY_USER_LOCKED. Lockouts expire after 15 minutes.',
     ['H9', 'H28']),
    ('C', 'Lateral movement between workstations is blocked',
     'From Student1, a connection to the domain controller’s login service succeeds, while connections to Instructor1 (another '
     'zone) and Student2 (same zone) time out. The firewall logs the cross-zone attempt; the same-zone attempt is dropped by '
     'Student2’s own firewall.',
     ['H15', 'H33', 'H34']),
    ('D', 'An unregistered device gets no address and no access',
     'Student2’s network card is given an unregistered MAC address. It receives no DHCP address, and everything it sends, even from '
     'a self-assigned address, is blocked and logged. With its registered MAC it receives its reserved address again.',
     ['H7', 'H21', 'H22', 'H23', 'H24', 'H25', 'H26', 'H27']),
    ('E', 'Security events are collected centrally',
     'Workstation security events reach the domain controller within seconds through Windows Event Forwarding; every PDP decision is '
     'an event in the domain controller’s Application log; network decisions are in the firewall log.',
     ['H11', 'H36']),
]

demo_html = ''.join(
    f'<div class="demo"><h3><span class="dl">Demo {k}</span> {E(t)}</h3><p>{E(d)}</p>{figs(*fs)}</div>' for k, t, d, fs in DEMOS)

PAGE = f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ZTNA D202 Evaluator Review</title>
<meta name="description" content="Review material for the Post-Simulation Readiness Evaluation of the ZTNA model for Computer Laboratory D202.">
<style>
:root{{--bg:#fff;--bg2:#f6f8fb;--ink:#0f172a;--muted:#5b6678;--line:#e2e8f0;--card:#fff;--accent:#2563eb;--chip:#eef2ff;--chip-ink:#3730a3}}
@media (prefers-color-scheme: dark){{:root:not([data-theme="light"]){{--bg:#0b1020;--bg2:#111829;--ink:#e6eaf2;--muted:#9aa6bb;--line:#24304a;--card:#121a2e;--accent:#6ea8ff;--chip:#1e2547;--chip-ink:#c7d2fe}}}}
:root[data-theme="dark"]{{--bg:#0b1020;--bg2:#111829;--ink:#e6eaf2;--muted:#9aa6bb;--line:#24304a;--card:#121a2e;--accent:#6ea8ff;--chip:#1e2547;--chip-ink:#c7d2fe}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 "Inter","Segoe UI",system-ui,-apple-system,Roboto,Arial,sans-serif}}
a{{color:var(--accent)}}
.wrap{{max-width:980px;margin:0 auto;padding:0 16px}}
header{{background:var(--bg2);border-bottom:1px solid var(--line);padding:40px 0 28px}}
h1{{font-size:clamp(1.6rem,3.6vw,2.2rem);line-height:1.2;margin:6px 0 10px}}
.kicker{{text-transform:uppercase;letter-spacing:.12em;font-size:.78rem;color:var(--muted)}}
section{{padding:36px 0;border-bottom:1px solid var(--line)}}
h2{{font-size:1.4rem;margin:0 0 8px}}
h3{{font-size:1.1rem;margin:22px 0 6px}}
.dl{{display:inline-block;background:var(--ink);color:var(--bg);border-radius:6px;padding:1px 8px;font-size:.85rem;margin-right:6px}}
p{{margin:8px 0}}
.muted{{color:var(--muted)}}
.box{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 18px;margin:14px 0}}
ol.toc{{margin:6px 0;padding-left:20px}}
table{{width:100%;border-collapse:collapse;font-size:.93rem;margin:10px 0}}
th,td{{border:1px solid var(--line);padding:8px 10px;text-align:left;vertical-align:top}}
th{{background:var(--bg2)}}
td.n{{white-space:nowrap;font-variant-numeric:tabular-nums}}
.tbl{{overflow-x:auto}}
.items{{font-size:.88rem;color:var(--muted)}}
.items span{{display:inline-block;background:var(--chip);color:var(--chip-ink);border-radius:999px;padding:1px 9px;margin:0 2px;font-weight:600}}
.figs{{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin:12px 0}}
@media (max-width:700px){{.figs{{grid-template-columns:1fr}}}}
figure{{margin:0;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}}
figure img{{width:100%;display:block;background:#0b1220}}
figcaption{{padding:8px 10px;font-size:.86rem}}
figcaption b{{display:block;margin-bottom:2px}}
figcaption span{{color:var(--muted)}}
.arch{{background:#fff;border:1px solid var(--line);border-radius:10px;padding:8px}}
.arch img{{width:100%;display:block}}
ul{{margin:6px 0;padding-left:20px}}
li{{margin:4px 0}}
footer{{padding:28px 0;color:var(--muted);font-size:.9rem}}
@media print{{header{{background:none}}section{{break-inside:auto}}figure{{break-inside:avoid}}}}
</style>
</head>
<body>
<header><div class="wrap">
  <div class="kicker">Phase 3 · Post-Simulation Readiness Evaluation · Review material</div>
  <h1>Zero Trust Network Access model for Computer Laboratory D202</h1>
  <p>This page presents the virtual simulation of the proposed ZTNA model for your review before you complete the
     <b>Post-Simulation Readiness Evaluation (Appendix B, Part II)</b>. It covers the same steps that were shown in the live
     demonstration, documented with screen captures from the running test-bed. Reading it takes about 30 to 40 minutes.</p>
  <p class="muted">Figure numbers (H1 to H36) are the same as in Appendix H of the manuscript. Click any figure to open it at full size.</p>
</div></header>

<main class="wrap">

<section>
  <h2>How to use this page</h2>
  <ol class="toc">
    <li><a href="#built">What was built</a></li>
    <li><a href="#segmentation">Network zones and the enforcement point</a></li>
    <li><a href="#identity">Identity, roles and policy decisions</a></li>
    <li><a href="#demos">The five demonstrations</a></li>
    <li><a href="#results">Measured performance</a></li>
    <li><a href="#operations">What running it would involve</a></li>
    <li><a href="#limits">Limitations and changes from the plan</a></li>
  </ol>
  <div class="box">
    <b>Where to look for each item.</b> Items C1 to C6 ask about the actual laboratory and its staff, so they rely mainly on your
    own knowledge; the sections below provide context for them. Items D1 to D3 ask for your judgment after reviewing the simulation.
    <div class="tbl"><table>
      <tr><th>Item</th><th>Topic</th><th>Most relevant sections</th></tr>
      <tr><td>C1</td><td>Infrastructure support for identity-aware access control</td><td><a href="#identity">3</a>, <a href="#operations">6</a></td></tr>
      <tr><td>C2</td><td>Network support for segmentation (VLAN and firewall)</td><td><a href="#segmentation">2</a>, <a href="#demos">4 (Demo C)</a></td></tr>
      <tr><td>C3</td><td>IT personnel capability to administer and maintain it</td><td><a href="#operations">6</a></td></tr>
      <tr><td>C4</td><td>Workload given current staffing</td><td><a href="#operations">6</a></td></tr>
      <tr><td>C5</td><td>Institutional review and approval process</td><td><a href="#limits">7</a></td></tr>
      <tr><td>C6</td><td>Least-privilege enforcement</td><td><a href="#identity">3</a>, <a href="#demos">4 (Demos A and C)</a></td></tr>
      <tr><td>D1</td><td>Suitability of the Proxmox-based simulation as a validation step</td><td><a href="#built">1</a>, <a href="#results">5</a></td></tr>
      <tr><td>D2</td><td>Integration without significant disruption</td><td><a href="#operations">6</a>, <a href="#limits">7</a></td></tr>
      <tr><td>D3</td><td>Overall readiness for deployment</td><td>All sections</td></tr>
      <tr><td>D4</td><td>Risks and mitigations (open-ended)</td><td><a href="#limits">7</a> and your own experience</td></tr>
    </table></div>
  </div>
</section>

<section id="built">
  <h2>1. What was built</h2>
  <p>The model was built in a Proxmox Virtual Environment test-bed of five virtual machines: a Windows Server 2022 domain controller
     (DC01), an OPNsense firewall, one instructor workstation and two student workstations (Windows 11). A VLAN-aware virtual bridge
     separates three zones: Students (VLAN 11), Instructor (VLAN 20) and Server (VLAN 30). Only the firewall carries all three VLANs,
     so traffic between zones must pass it. All user accounts are synthetic; no real person’s data was used.</p>
  <div class="arch"><img src="assets/architecture.svg" alt="Test-bed architecture: three VLAN zones connected only through the OPNsense firewall; DC01 in the Server zone"></div>
  {items('D1')}
  {figs('H1', 'H3', 'H2', 'H4', 'H5')}
</section>

<section id="segmentation">
  <h2>2. Network zones and the enforcement point</h2>
  <p>OPNsense is the Policy Enforcement Point (PEP). Each zone has its own rules: workstations may reach only the domain services of
     DC01 (Kerberos, LDAP, DNS, SMB for Group Policy) and DNS; instructors may also ping student workstations; DC01 may reach
     workstations only for remote administration (WinRM). Everything else is denied and logged. Inside a zone, where traffic does
     not pass the firewall, each workstation’s Windows firewall is controlled only by Group Policy and blocks connections from
     other workstations.</p>
  {items('C2', 'C6')}
  {figs('H18', 'H19', 'H20')}
</section>

<section id="identity">
  <h2>3. Identity, roles and policy decisions</h2>
  <p>The Policy Decision Point (PDP) is Active Directory together with a policy decision script on DC01. Access is granted to role
     groups (students, instructors, administrators), never to individuals. Group Policy sets the logon rights: students may use any
     student workstation, but not the instructor workstation or the server. For each request, the script checks the user (exists,
     enabled, not locked, has a role), then the device (registered, domain member, MAC address matches), then the policy matrix,
     and returns Allow or Deny with a reason code. Anything not explicitly allowed is denied.</p>
  {items('C1', 'C6')}
  {figs('H6', 'H8', 'H13', 'H14', 'H10', 'H12')}
</section>

<section id="demos">
  <h2>4. The five demonstrations</h2>
  <p>These are the demonstrations performed in the live session. Each is shown here with the screens captured when it was run on the
     test-bed.</p>
  {demo_html}
</section>

<section id="results">
  <h2>5. Measured performance</h2>
  <p>Six engineering indicators were measured. Each was measured in five independent trials of 100 events; the five-trial mean was
     compared with the threshold set in the methodology (Table 2 of the manuscript).</p>
  <div class="tbl"><table>
    <tr><th>Indicator</th><th>Threshold</th><th>Five-trial mean</th></tr>
    <tr><td>Authentication latency (end-to-end at the workstation)</td><td class="n">≤ 300 ms (mean and 95th percentile)</td><td class="n">17.6 ms (95th percentile 19.8 ms)</td></tr>
    <tr><td>Policy decision latency</td><td class="n">≤ 200 ms</td><td class="n">4.36 ms</td></tr>
    <tr><td>RBAC enforcement accuracy</td><td class="n">≥ 99%</td><td class="n">100%</td></tr>
    <tr><td>Unauthorized authentication blocking</td><td class="n">≥ 99%</td><td class="n">100%</td></tr>
    <tr><td>Micro-segmentation rule drops (cross-zone attempts)</td><td class="n">≥ 99%</td><td class="n">100%</td></tr>
    <tr><td>Logging completeness (granted and denied events)</td><td class="n">100%</td><td class="n">100%</td></tr>
  </table></div>
  <div class="box">
    <b>How the measurements were made.</b>
    <ul>
      <li>Every test used a fixed list of cases prepared before the test; the expected result of each case was derived from the
          policy, not from the system being tested.</li>
      <li>Each trial was an independent run with the order of cases shuffled; times were measured inside the virtual machines.</li>
      <li>Every figure was recalculated from the raw per-event records.</li>
      <li>For logging and segmentation, deliberately broken records were added as a check, and the counting reported exactly those
          as missing.</li>
      <li>The first RBAC run scored 95%. The cause was an error in how the policy script read account attributes; it was corrected
          and the test repeated (two of the three refinement cycles allowed by the methodology were used).</li>
    </ul>
  </div>
  {items('D1', 'D3')}
  {figs('H29', 'H30', 'H31', 'H32', 'H35')}
</section>

<section id="operations">
  <h2>6. What running it would involve</h2>
  <p>The model uses only software that is already available or free: Active Directory and Group Policy (Windows Server) and the
     open-source OPNsense firewall. Proxmox was used only for testing. The recurring administrative tasks would be:</p>
  <div class="tbl"><table>
    <tr><th>Task</th><th>When</th><th>What it involves</th></tr>
    <tr><td>Onboard and offboard students</td><td>Each term</td><td>Create or disable accounts and add them to the student group; access follows from the group</td></tr>
    <tr><td>Register a workstation</td><td>When a PC is added or its network card replaced</td><td>A DHCP reservation and registered-MAC entry on the firewall, and a computer object with its MAC address in Active Directory</td></tr>
    <tr><td>Change who may access what</td><td>When roles or policy change</td><td>Edit the role groups or the firewall rules, and keep the policy matrix and firewall consistent</td></tr>
    <tr><td>Respond to lockouts</td><td>As needed</td><td>Lockouts expire after 15 minutes; staff can unlock earlier from Active Directory</td></tr>
    <tr><td>Review logs</td><td>Routinely</td><td>Forwarded workstation events and PDP decisions on the domain controller; the firewall log on OPNsense</td></tr>
  </table></div>
  <p>The skills involved are Active Directory and Group Policy administration, VLAN configuration on the switches, and OPNsense firewall
     administration. In the actual laboratory the VLANs would be configured on the access switches instead of a virtual bridge.</p>
  {items('C1', 'C3', 'C4', 'D2')}
</section>

<section id="limits">
  <h2>7. Limitations and changes from the plan</h2>
  <ul>
    <li>The test-bed has five virtual machines and synthetic accounts. The actual laboratory has more users and devices, and response
        times may be higher under real load.</li>
    <li>Lateral movement was tested with TCP connection attempts only.</li>
    <li>MAC addresses can be spoofed. The model also requires domain membership; port-based authentication (IEEE 802.1X) is recommended
        for a production deployment if the switches support it.</li>
    <li>The firewall log is kept on the firewall itself; a production deployment should forward it to a central log server.</li>
    <li>Changes from the original plan: Windows Server 2022 instead of 2019; reservations-only DHCP with no dynamic range; the
        firewall’s local log instead of a remote syslog server.</li>
    <li>Defects found during testing (account-lockout auditing not enabled, workstation firewall logging inactive, the policy script
        error above) were corrected and are listed as recommendations in Chapter 3.</li>
    <li>Moving from the test-bed to the actual laboratory would require the University’s review and approval of the new controls.</li>
  </ul>
  {items('C5', 'D2', 'D4')}
</section>

<section>
  <h2>Next step</h2>
  <p>Please complete the Post-Simulation Readiness Evaluation (Appendix B, Part II) and the informed consent form attached to our email,
     and return them by email. If you would like a live online demonstration or have any questions, reply to the email and we will
     arrange it.</p>
  <p class="muted">Source code, the policy matrix, test designs and per-trial results are in the
     <a href="https://github.com/kcayboen/zero-trust-lab-ztna">project repository</a>. This review page is frozen as release
     <code>evaluation-2026-11-19</code>.</p>
</section>
</main>
<footer><div class="wrap">Undergraduate thesis, School of Information Technology, University of Baguio, 2026.</div></footer>
</body>
</html>
'''
open(sys.argv[2], 'w').write(PAGE)
print('wrote', sys.argv[2], len(FIGS), 'figures available')
