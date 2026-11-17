#!/usr/bin/env python3
"""Build the SOP 3 table for S2 (PDP decision latency + RBAC accuracy) from raw rows.

Recomputes every value from results/raw/S2-pdp-rbac/S2-cycle<N>/pdp-S2-T*.csv (not from the
PDP's summary JSON) and checks each Expected against plan/cases/S2-rbac-cases.csv.
"""
import csv, glob, json, math, os, statistics

SIM = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(SIM, 'results', 'raw', 'S2-pdp-rbac')
cases = {r['CaseId']: r for r in csv.DictReader(open(os.path.join(SIM, 'plan', 'cases', 'S2-rbac-cases.csv')))}


def p95(v):
    s = sorted(v); return s[max(0, math.ceil(len(s) * 0.95) - 1)]


rows_out = []
for cyc in sorted(glob.glob(os.path.join(RAW, 'S2-cycle*'))):
    c = os.path.basename(cyc).replace('S2-', '')
    for f in sorted(glob.glob(os.path.join(cyc, 'pdp-S2-T?.csv'))):
        t = os.path.basename(f)[7:9]
        rows = list(csv.DictReader(open(f)))
        assert len(rows) == 100 and len({r['CaseId'] for r in rows}) == 100, f
        for r in rows:
            assert r['Expected'] == cases[r['CaseId']]['Expected'], (f, r['CaseId'])
        lat = [float(r['LatencyMs']) for r in rows]
        correct = sum(r['Decision'] == r['Expected'] for r in rows)
        summ = json.load(open(f.replace('.csv', '-summary.json'), encoding='utf-8-sig'))
        rows_out.append(dict(cycle=c, trial=t, n=len(rows), correct=correct, acc=100.0 * correct / len(rows),
                             mean=statistics.mean(lat), p95=p95(lat), mx=max(lat), warm=summ.get('WarmUpMs'),
                             rolemis=sum(r['ExpectedRole'] != r['Role'] for r in rows),
                             allow=sum(r['Decision'] == 'Allow' for r in rows)))

out = os.path.join(SIM, 'results', 'processed', 'SOP3-S2-pdp-rbac.csv')
with open(out, 'w', newline='') as fh:
    w = csv.writer(fh)
    w.writerow(['Cycle', 'Indicator', 'T1', 'T2', 'T3', 'T4', 'T5', 'Mean', 'Threshold', 'Pass'])
    for c in sorted({r['cycle'] for r in rows_out}):
        rs = sorted([r for r in rows_out if r['cycle'] == c], key=lambda r: r['trial'])
        pad = lambda v: v + [''] * (5 - len(v))
        for name, key, thr, ok in [('Policy decision latency mean (ms)', 'mean', '<=200', lambda m: m <= 200),
                                   ('Policy decision latency p95 (ms)', 'p95', '(reported)', None),
                                   ('RBAC enforcement accuracy (%)', 'acc', '>=99', lambda m: m >= 99),
                                   ('Warm-up call, discarded (ms)', 'warm', '(declared)', None)]:
            vals = [r[key] for r in rs]
            m = statistics.mean(vals)
            complete = len(rs) == 5
            w.writerow([c, name] + pad([f'{v:.3f}' for v in vals]) + [f'{m:.3f}' if complete else f'{m:.3f} (n={len(rs)})', thr,
                        ('' if ok is None else ('PASS' if ok(m) and complete else ('FAIL' if complete else 'incomplete')))])
print(open(out).read())
for r in rows_out:
    print(f"{r['cycle']} {r['trial']} correct={r['correct']} allow={r['allow']} roleMismatch={r['rolemis']} max={r['mx']:.1f}ms")
