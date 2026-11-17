#!/usr/bin/env python3
r"""Count one S5 trial (plan/s5-segmentation-design.md).

Usage: s5_count.py <T1..T5> [--dry] [--cycle S5-cycle0] [--offline] [--negcontrol]

--negcontrol  offline, with two deliberately broken ground-truth rows (a CrossZone source port -> 39999,
              a SameVlan attempt marked Connected=True): exactly those two must be reported not dropped.

CrossZone (indicator): dropped <=> OPNsense `block in` line(s) for the exact 4-tuple within +-30 s,
no `pass` line for it, and the client saw a silent timeout (Connected=False, no error text).
Packet level: block lines / (block + pass lines) over the 100 tuples. Firewall counters: packet delta of
block rules 300/700/900/1000 from `pfctl -vvsr` saved before/after the trial by s5_trial.sh.
SameVlan (reported separately): dropped <=> silent timeout at the client (Connected=False, no error: an
unfiltered closed port would answer RST, an unfiltered open port would connect). Logged <=> `DROP TCP`
line(s) in the TARGET's pfirewall.log for the exact tuple within +-60 s (log is local SGT time). Windows
logs only drops to ports with a listening service (stealth-mode drops of closed ports are not logged;
found in the S5 dry run 2026-11-14), so Logged is expected exactly for LISTENING ports. Also checks
OPNsense saw nothing.
--offline re-counts from the files saved in results/raw/S5-lateral/<cycle>/.
"""
import argparse, csv, datetime as dt, os, re, subprocess, sys, time
from collections import Counter

SIM = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(SIM, 'tools')
HOSTS = {'STUDENT1': 15986, 'STUDENT2': 15988, 'INSTRUCTOR1': 15987, 'DC01': 15985}
IP_HOST = {'10.20.11.21': 'STUDENT1', '10.20.11.22': 'STUDENT2'}
BLOCK_RULES = {'140fc678-5810-4c1e-8c14-091743669196': '300', '09291a15-168a-47d0-adb6-5bba754c9de2': '700',
               'cabf7b20-3357-43bb-9536-18373cd09172': '900', '864c268d-dd09-4d54-a751-13a6dd24dff6': '1000'}
SGT = dt.timezone(dt.timedelta(hours=8))
# Ports with a listening service on Student1/Student2 (Get-NetTCPConnection -State Listen, 2026-11-14)
LISTENING = {445, 3389, 5985, 135, 139}
SP = os.environ.get('ZTNA_TMP', '/tmp/ztna')


def iso(s):
    return dt.datetime.strptime(s[:23], '%Y-%m-%dT%H:%M:%S.%f').replace(tzinfo=dt.timezone.utc)


def get(port, remote, local):
    r = subprocess.run([os.path.join(TOOLS, 'get.sh'), str(port), remote, local], capture_output=True, text=True)
    if not r.stdout.startswith('OK'):
        sys.exit(f'download failed: {remote} {r.stdout} {r.stderr}')


def lab_now():
    path = os.path.join(SP, 's5now.ps1')
    open(path, 'w').write("(Get-Date).ToUniversalTime().ToString('o')")
    r = subprocess.run(['node', 'win.js', 'psb64', path], cwd=os.path.join(TOOLS, 'winrm'),
                       env={**os.environ, 'W_PORT': '15985'}, capture_output=True, text=True, timeout=60)
    return dt.datetime.fromisoformat(r.stdout.strip()[:26] + '+00:00')


def pf_packets(path):
    """Sum the 'Packets:' counters of the four block rules (one pf rule per port/proto expansion)."""
    tot, cur = Counter(), None
    for line in open(path):
        m = re.search(r'label "([0-9a-f-]{36})"', line)
        if line.startswith('@'):
            cur = m.group(1) if m and m.group(1) in BLOCK_RULES else None
        elif cur and 'Packets:' in line:
            tot[BLOCK_RULES[cur]] += int(re.search(r'Packets:\s*(\d+)', line).group(1))
    return tot


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('trial'); ap.add_argument('--dry', action='store_true')
    ap.add_argument('--cycle', default='S5-cycle0'); ap.add_argument('--offline', action='store_true')
    ap.add_argument('--negcontrol', action='store_true')
    a = ap.parse_args()
    a.offline = a.offline or a.negcontrol
    t = a.trial
    root = r'C:\ZTNA\results\dryrun\raw' if a.dry else r'C:\ZTNA\results\raw'
    out = os.path.join(SIM, 'results', 'raw', 'S5-lateral', 'dryrun' if a.dry else a.cycle)
    os.makedirs(out, exist_ok=True)
    cases = {r['CaseId']: r for r in csv.DictReader(open(os.path.join(SIM, 'plan', 'cases', 'S5-lateral-cases.csv')))}

    gt = {}
    for h, port in HOSTS.items():
        f = os.path.join(out, f'net-S5-{t}-{h}.csv')
        if not a.offline:
            get(port, rf'{root}\net-S5-{t}-{h}.csv', f)
        for r in csv.DictReader(open(f)):
            gt[r['CaseId']] = r
    assert sorted(gt) == sorted(cases), f'ground truth incomplete: {len(gt)} of {len(cases)}'
    broken = []
    if a.negcontrol:
        cid = sorted(c for c in gt if cases[c]['Family'] == 'CrossZone')[0]; gt[cid]['SrcPort'] = '39999'; broken.append(cid)
        cid = sorted(c for c in gt if cases[c]['Family'] == 'SameVlan')[0]; gt[cid]['Connected'] = 'True'; broken.append(cid)
    times = [iso(r['TimestampUtc']) for r in gt.values()]

    if not a.offline:   # pfirewall.log flushes lazily (<= ~40 s); compare with the LAB clock, not the laptop's
        ready = max(times) + dt.timedelta(seconds=60)
        now = lab_now()
        if now < ready:
            print(f'waiting {(ready - now).total_seconds():.0f} s for log flush...'); time.sleep((ready - now).total_seconds())

    # OPNsense filter log: lines from the four hosts with source ports 30000-36999
    fwf = os.path.join(out, f's5-{t}-opnsense-sink.txt')
    if a.offline:
        raw = open(fwf).read().splitlines()
    else:
        r = subprocess.run([os.path.join(TOOLS, 'opn.sh'),
                            "sh -c 'grep -hE \",10\\.20\\.(11\\.2[12]|20\\.21|30\\.10),10\\.20\\.[0-9.]+,3[0-6][0-9]{3},\" /var/log/filter/filter_*.log'"],
                           capture_output=True, text=True, timeout=120)
        raw = r.stdout.splitlines()
        open(fwf, 'w').write('\n'.join(raw) + '\n')
    fw = []
    for line in raw:
        b = line.split('] ', 1)[-1].split(',')
        if len(b) < 22 or not b[20].isdigit():
            continue
        fw.append(dict(time=dt.datetime.fromisoformat(line.split(' ')[1]), label=b[3], action=b[6], dir=b[7],
                       src=b[18], dst=b[19], sport=int(b[20]), dport=int(b[21])))

    # target pfirewall.log (Student1, Student2) for the SameVlan family
    pfw = []
    for h in ('STUDENT1', 'STUDENT2'):
        f = os.path.join(out, f's5-{t}-pfirewall-{h}.log')
        if not a.offline:   # the firewall service holds the log open: copy it with shared access first
            path = os.path.join(SP, 's5copy.ps1')
            open(path, 'w').write(r"$src = [IO.File]::Open('C:\Windows\System32\LogFiles\Firewall\pfirewall.log', 'Open', 'Read', 'ReadWrite'); "
                                  r"$dst = [IO.File]::Create('C:\ZTNA\results\pfirewall-copy.log'); $src.CopyTo($dst); $dst.Close(); $src.Close(); 'copied'")
            subprocess.run(['node', 'win.js', 'psb64', path], cwd=os.path.join(TOOLS, 'winrm'),
                           env={**os.environ, 'W_PORT': str(HOSTS[h])}, capture_output=True, text=True, timeout=60)
            get(HOSTS[h], r'C:\ZTNA\results\pfirewall-copy.log', f)
        for line in open(f, 'rb').read().replace(b'\0', b'').decode('ascii', 'replace').splitlines():
            p = line.split()
            if len(p) < 8 or line.startswith('#') or not p[6].isdigit() or not p[7].isdigit():
                continue
            when = dt.datetime.strptime(p[0] + ' ' + p[1], '%Y-%m-%d %H:%M:%S').replace(tzinfo=SGT)
            pfw.append(dict(host=h, time=when, action=p[2], proto=p[3], src=p[4], dst=p[5], sport=int(p[6]), dport=int(p[7])))

    res, blk_lines, pass_lines = [], 0, 0
    for cid, g in sorted(gt.items()):
        c = cases[cid]; when = iso(g['TimestampUtc'])
        key = (g['SrcIp'], int(g['SrcPort']), g['DstIp'], int(g['DstPort']))
        near = [x for x in fw if (x['src'], x['sport'], x['dst'], x['dport']) == key
                and abs((x['time'] - when).total_seconds()) <= 30]
        blocks = [x for x in near if x['action'] == 'block' and x['dir'] == 'in']
        passes = [x for x in near if x['action'] == 'pass']
        silent = g['Connected'] == 'False' and not g['Error']
        if c['Family'] == 'CrossZone':
            blk_lines += len(blocks); pass_lines += len(passes)
            dropped = bool(blocks) and not passes and silent
            rules = ','.join(sorted({BLOCK_RULES.get(x['label'], x['label'][:8]) for x in blocks})) or '-'
            ev = f"block x{len(blocks)} rule {rules}; pass x{len(passes)}; client connected={g['Connected']} err='{g['Error']}'"
        else:
            target = IP_HOST[g['DstIp']]
            drops = [x for x in pfw if x['host'] == target and x['action'] == 'DROP' and x['proto'] == 'TCP'
                     and (x['src'], x['sport'], x['dst'], x['dport']) == key and abs((x['time'] - when).total_seconds()) <= 60]
            dropped = silent and not near
            logged = bool(drops)
            want_log = int(g['DstPort']) in LISTENING
            ev = (f"{target} pfirewall DROP x{len(drops)} (log expected: {want_log}); OPNsense lines x{len(near)}; "
                  f"client connected={g['Connected']} err='{g['Error']}'")
        if c['Family'] == 'CrossZone':
            logged, want_log = bool(blocks), True
        res.append(dict(CaseId=cid, Family=c['Family'], Source=g['Workstation'], Target=c['Resource'], Port=g['DstPort'],
                        Dropped=dropped, Logged=logged, LogExpected=want_log, Evidence=ev, TimestampUtc=g['TimestampUtc']))

    pfd = {}
    fb, fa = os.path.join(out, f'pf-{t}-before.txt'), os.path.join(out, f'pf-{t}-after.txt')
    if os.path.exists(fb) and os.path.exists(fa):
        b, af = pf_packets(fb), pf_packets(fa)
        pfd = {k: af[k] - b[k] for k in sorted(set(b) | set(af), key=int)}

    outf = os.path.join(out, f's5-{t}-cases' + ('-negcontrol' if a.negcontrol else '-offline' if a.offline else '') + '.csv')
    with open(outf, 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=list(res[0])); w.writeheader(); w.writerows(res)
    with open(os.path.join(out, f's5-{t}-summary' + ('-negcontrol' if a.negcontrol else '-offline' if a.offline else '') + '.csv'), 'w', newline='') as fh:
        w = csv.writer(fh)
        cz = [r for r in res if r['Family'] == 'CrossZone']; sv = [r for r in res if r['Family'] == 'SameVlan']
        w.writerow(['Trial', 'CrossZoneDropped', 'CrossZoneCases', 'BlockLines', 'PassLines', 'SameVlanDropped', 'SameVlanCases',
                    'SameVlanLogged', 'SameVlanLogExpected', 'SameVlanLogAsExpected']
                   + [f'pfDeltaRule{k}' for k in pfd])
        w.writerow([t, sum(r['Dropped'] for r in cz), len(cz), blk_lines, pass_lines, sum(r['Dropped'] for r in sv), len(sv),
                    sum(r['Logged'] for r in sv), sum(r['LogExpected'] for r in sv), sum(r['Logged'] == r['LogExpected'] for r in sv)]
                   + list(pfd.values()))
    cz = [r for r in res if r['Family'] == 'CrossZone']; sv = [r for r in res if r['Family'] == 'SameVlan']
    if a.negcontrol:
        nd = sorted(r['CaseId'] for r in res if not r['Dropped'])
        print(f'NEGATIVE CONTROL {t}: broke {broken}; reported not dropped {nd} -> ' + ('OK' if nd == sorted(broken) else 'FAILED'))
    pk = 100.0 * blk_lines / (blk_lines + pass_lines) if blk_lines + pass_lines else 0.0
    print(f"S5 {t}{' (dry)' if a.dry else ''}{' (offline)' if a.offline else ''}: CrossZone dropped {sum(r['Dropped'] for r in cz)}/{len(cz)} "
          f"| packets blocked {blk_lines}/{blk_lines + pass_lines} = {pk:.1f}% | SameVlan dropped {sum(r['Dropped'] for r in sv)}/{len(sv)}, "
          f"logged {sum(r['Logged'] for r in sv)} (expected {sum(r['LogExpected'] for r in sv)}, as expected {sum(r['Logged'] == r['LogExpected'] for r in sv)}/{len(sv)}) "
          f"| pf block-rule packet deltas {pfd} (sum {sum(pfd.values())} >= block lines {blk_lines}: {sum(pfd.values()) >= blk_lines})")
    for r in res:
        if not r['Dropped'] or r['Logged'] != r['LogExpected']:
            print('  CHECK', r['CaseId'], r['Family'], r['Source'], '->', r['Target'], r['Port'], r['Evidence'])


if __name__ == '__main__':
    main()
