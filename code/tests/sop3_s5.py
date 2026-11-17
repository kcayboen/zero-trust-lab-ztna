#!/usr/bin/env python3
"""SOP 3 table for S5 (micro-segmentation, threshold >= 99 %) from the per-trial files of s5_count.py.

Indicator = CrossZone attempts dropped at OPNsense (attempt level), with the packet level (block lines /
all lines for the test tuples) and the pf block-rule counter deltas as Table 2's "firewall counters".
SameVlan (owner decision: reported separately) is a second block of rows, never part of the indicator.
"""
import csv, os, statistics, sys

SIM = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
cyc = sys.argv[1] if len(sys.argv) > 1 else 'S5-cycle0'
RAW = os.path.join(SIM, 'results', 'raw', 'S5-lateral', cyc)
case_ids = sorted(r['CaseId'] for r in csv.DictReader(open(os.path.join(SIM, 'plan', 'cases', 'S5-lateral-cases.csv'))))
T = ['T1', 'T2', 'T3', 'T4', 'T5']
summ = {t: next(csv.DictReader(open(os.path.join(RAW, f's5-{t}-summary.csv')))) for t in T}
for t in T:
    rows = list(csv.DictReader(open(os.path.join(RAW, f's5-{t}-cases.csv'))))
    assert sorted(r['CaseId'] for r in rows) == case_ids, t

i = lambda t, k: int(summ[t][k])
pf_cols = [k for k in summ['T1'] if k.startswith('pfDeltaRule')]
lines = [
    ('S5 micro-segmentation: cross-zone attempts dropped (%) [n=100/trial]', lambda t: 100.0 * i(t, 'CrossZoneDropped') / i(t, 'CrossZoneCases'), '>=99', True),
    ('  packets blocked at OPNsense (%) [block lines / all lines of the test tuples]',
     lambda t: 100.0 * i(t, 'BlockLines') / (i(t, 'BlockLines') + i(t, 'PassLines')), '(reported)', False),
    ('  packets blocked (count, SYN + retransmits)', lambda t: i(t, 'BlockLines'), '(reported)', False),
    ('  pf block-rule counter delta, rules 300/700/900/1000 (packets)', lambda t: sum(i(t, k) for k in pf_cols), '(>= block lines)', False),
    ('Same-VLAN (separate): student<->student attempts dropped by host firewall (%) [n=20/trial]',
     lambda t: 100.0 * i(t, 'SameVlanDropped') / i(t, 'SameVlanCases'), '(reported)', False),
    ('  same-VLAN drops logged in target pfirewall.log (count; expected 10 = ports with a listening service)',
     lambda t: i(t, 'SameVlanLogged'), '(expected 10)', False),
]
out = os.path.join(SIM, 'results', 'processed', 'SOP3-S5-segmentation.csv')
with open(out, 'w', newline='') as fh:
    w = csv.writer(fh)
    w.writerow(['Cycle', 'Indicator', 'T1', 'T2', 'T3', 'T4', 'T5', 'Mean', 'Threshold', 'Pass'])
    for name, f, thr, scored in lines:
        vals = [f(t) for t in T]
        m = statistics.mean(vals)
        w.writerow([cyc, name] + [f'{v:.3f}' if isinstance(v, float) else str(v) for v in vals] +
                   [f'{m:.3f}', thr, ('PASS' if m >= 99 else 'FAIL') if scored else ''])
    neg = [os.path.join(RAW, f's5-{t}-summary-negcontrol.csv') for t in T]
    if all(os.path.exists(f) for f in neg):
        v = [next(csv.DictReader(open(f))) for f in neg]
        w.writerow([cyc, 'Negative control: 1 broken cross-zone + 1 broken same-VLAN case per trial (cross-zone dropped, %)']
                   + [f"{100.0 * int(x['CrossZoneDropped']) / int(x['CrossZoneCases']):.3f}" for x in v] + ['99.000', '(expected 99)',
                   'exactly the broken cases reported not dropped (s5_count.py --negcontrol)'])
    w.writerow([])
    w.writerow(['Note', 'Dropped (cross-zone) = OPNsense block-in line(s) for the exact 4-tuple within +-30 s, no pass line, and a silent '
                'client timeout. Same-VLAN dropped = silent client timeout with no OPNsense line; Windows logs drops only for '
                'listening ports. Method: plan/s5-segmentation-design.md'])
print(open(out).read())
