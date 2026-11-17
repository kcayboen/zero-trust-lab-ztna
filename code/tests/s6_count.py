#!/usr/bin/env python3
r"""Count one S6 trial: was every ground-truth event captured in its sink? (plan/s6-logging-design.md)

Usage: s6_count.py <T1..T5> [--dry] [--cycle S6-cycle0] [--offline] [--negcontrol]

--offline     re-count from the files already saved in the cycle folder (no downloads, no sink queries;
              the runners' raw files on the hosts were moved to C:\ZTNA\results\raw\S6-cycle0 afterwards).
--negcontrol  offline, with one deliberately broken ground-truth row per family (user -> ghost99,
              PDP decision flipped, source port -> 49999): proves the counter reports exactly those 3 as missed.

1. Pull the runners' ground truth (auth-S6/net-S6 CSVs from the workstations, pdp-S6 CSV from DC01).
2. Wait until >= 70 s after the last ground-truth event (WEF max latency 5 s + heartbeat 60 s).
3. Query the sinks: DC01 ForwardedEvents (4624 type 2 / 4625 from the workstations), DC01 Application
   (ZTNA-PDP 4100/4101), OPNsense local filter log (direction in, exact src/dst ip+port).
4. Match per family, write results/raw/S6-logging/<cycle>/s6-<T>-cases.csv (one row per case with
   Captured + evidence) and the raw sink extracts next to it.
"""
import argparse, csv, datetime as dt, json, os, subprocess, sys, time
from collections import defaultdict

SIM = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(SIM, 'tools')
HOSTS = {'STUDENT1': 15986, 'STUDENT2': 15988, 'INSTRUCTOR1': 15987}
WS_IP = {'10.20.11.21': 'STUDENT1', '10.20.11.22': 'STUDENT2', '10.20.20.21': 'INSTRUCTOR1'}
SP = os.environ.get('ZTNA_TMP', '/tmp/ztna')


def iso(s):
    return dt.datetime.strptime(s[:23], '%Y-%m-%dT%H:%M:%S.%f').replace(tzinfo=dt.timezone.utc)


def get(port, remote, local):
    r = subprocess.run([os.path.join(TOOLS, 'get.sh'), str(port), remote, local], capture_output=True, text=True)
    if not r.stdout.startswith('OK'):
        sys.exit(f'download failed: {remote} {r.stdout} {r.stderr}')


def ps(port, script_text):
    path = os.path.join(SP, 's6q.ps1')
    open(path, 'w').write(script_text)
    r = subprocess.run(['node', 'win.js', 'psb64', path], cwd=os.path.join(TOOLS, 'winrm'),
                       env={**os.environ, 'W_PORT': str(port)}, capture_output=True, text=True, timeout=170)
    return r.stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('trial'); ap.add_argument('--dry', action='store_true'); ap.add_argument('--cycle', default='S6-cycle0')
    ap.add_argument('--offline', action='store_true'); ap.add_argument('--negcontrol', action='store_true')
    a = ap.parse_args()
    if a.negcontrol:
        a.offline = True
    t = a.trial
    root = r'C:\ZTNA\results\dryrun\raw' if a.dry else r'C:\ZTNA\results\raw'
    out = os.path.join(SIM, 'results', 'raw', 'S6-logging', 'dryrun' if a.dry else a.cycle)
    os.makedirs(out, exist_ok=True)
    cases = {r['CaseId']: r for r in csv.DictReader(open(os.path.join(SIM, 'plan', 'cases', 'S6-logging-cases.csv')))}

    # 1. ground truth
    gt = {}
    for h, port in HOSTS.items():
        for kind in ('auth', 'net'):
            f = os.path.join(out, f'{kind}-S6-{t}-{h}.csv')
            if not a.offline:
                get(port, rf'{root}\{kind}-S6-{t}-{h}.csv', f)
            for r in csv.DictReader(open(f)):
                gt[r['CaseId']] = dict(r, Kind=kind)
    f = os.path.join(out, f'pdp-S6-{t}.csv')
    if not a.offline:
        get(15985, rf'{root}\pdp-S6-{t}.csv', f)
    for r in csv.DictReader(open(f)):
        gt[r['CaseId']] = dict(r, Kind='pdp')
    assert sorted(gt) == sorted(cases), f'ground truth incomplete: {len(gt)} of {len(cases)}'
    if a.negcontrol:   # break one row per family; these three (and only these) must be reported missed
        broken = []
        cid = sorted(c for c, g in gt.items() if g['Kind'] == 'auth')[0]; gt[cid]['User'] = 'ghost99'; broken.append(cid)
        cid = sorted(c for c, g in gt.items() if g['Kind'] == 'pdp')[0]
        gt[cid]['Decision'] = 'Deny' if gt[cid]['Decision'] == 'Allow' else 'Allow'; broken.append(cid)
        cid = sorted(c for c, g in gt.items() if g['Kind'] == 'net')[0]; gt[cid]['SrcPort'] = '49999'; broken.append(cid)
    times = [iso(r['TimestampUtc']) for r in gt.values()]
    w0, w1 = min(times) - dt.timedelta(seconds=2), max(times) + dt.timedelta(seconds=10)

    # 2. wait for WEF delivery. "Now" must come from the lab (DC01) clock: the laptop clock differs
    #    from the lab clock by hours, so comparing lab timestamps with local time is meaningless.
    ready = max(times) + dt.timedelta(seconds=70)
    now = ready if a.offline else dt.datetime.fromisoformat(ps(15985, "(Get-Date).ToUniversalTime().ToString('o')").strip()[:26] + '+00:00')
    if now < ready:
        print(f'waiting {(ready - now).total_seconds():.0f} s for WEF delivery...'); time.sleep((ready - now).total_seconds())

    # 3a. Windows sinks on DC01 (exact TimeCreated filtering; Get-WinEvent bounds are not ms-precise)
    q = f'''$s = [DateTimeOffset]::Parse('{w0.isoformat()}').LocalDateTime; $e = [DateTimeOffset]::Parse('{w1.isoformat()}').LocalDateTime
$rows = New-Object System.Collections.Generic.List[string]
Get-WinEvent -FilterHashtable @{{LogName='ForwardedEvents'; Id=4624,4625; StartTime=$s.AddSeconds(-5); EndTime=$e.AddSeconds(5)}} -EA SilentlyContinue |
  ? {{ $_.TimeCreated -ge $s -and $_.TimeCreated -le $e }} | % {{
    $lt = if ($_.Id -eq 4624) {{ $_.Properties[8].Value }} else {{ $_.Properties[10].Value }}
    $rows.Add(('WIN|{{0}}|{{1}}|{{2}}|{{3}}|{{4}}' -f $_.TimeCreated.ToUniversalTime().ToString('o'), $_.Id, ($_.MachineName -split '\\.')[0].ToUpper(), $_.Properties[5].Value, $lt)) }}
Get-WinEvent -FilterHashtable @{{LogName='Application'; ProviderName='ZTNA-PDP'; Id=4100,4101; StartTime=$s.AddSeconds(-5); EndTime=$e.AddSeconds(5)}} -EA SilentlyContinue |
  ? {{ $_.TimeCreated -ge $s -and $_.TimeCreated -le $e }} | % {{
    $rows.Add(('APP|{{0}}|{{1}}|{{2}}' -f $_.TimeCreated.ToUniversalTime().ToString('o'), $_.Id, ($_.Message -replace '\\s+',' '))) }}
$rows | Set-Content C:\\ZTNA\\results\\s6sink-{t}.txt -Encoding UTF8
"rows=$($rows.Count)"'''
    sinkf = os.path.join(out, f's6-{t}-windows-sink.txt')
    if not a.offline:
        print('DC01 sink query:', ps(15985, q).strip())
        get(15985, rf'C:\ZTNA\results\s6sink-{t}.txt', sinkf)
    win, app = [], []
    for line in open(sinkf, encoding='utf-8-sig'):
        p = line.rstrip('\r\n').split('|')
        if p[0] == 'WIN':
            win.append(dict(time=p[1], id=int(p[2]), host=p[3], user=p[4].lower(), lt=p[5]))
        elif p[0] == 'APP':
            app.append(dict(time=p[1], id=int(p[2]), msg=p[3]))

    # 3b. OPNsense filter log (local): lines from the workstation IPs with source ports 40000-46999
    ports = {int(r['SrcPort']) for r in gt.values() if r['Kind'] == 'net'}
    fwf = os.path.join(out, f's6-{t}-opnsense-sink.txt')
    if a.offline:
        raw_lines = open(fwf).read().splitlines()
    else:
        r = subprocess.run([os.path.join(TOOLS, 'opn.sh'),
                            "sh -c 'grep -hE \",10\\.20\\.(11\\.2[12]|20\\.21),10\\.20\\.[0-9.]+,4[0-6][0-9]{3},\" /var/log/filter/filter_*.log'"],
                           capture_output=True, text=True, timeout=120)
        raw_lines = r.stdout.splitlines()
    fw = []
    for line in raw_lines:
        if not line.strip():
            continue
        body = line.split('] ', 1)[-1].split(',')
        if len(body) < 22:
            continue
        try:
            sport = int(body[20])
        except ValueError:
            continue
        if sport not in ports and not a.negcontrol:
            continue
        stamp = line.split(' ')[1]
        fw.append(dict(time=stamp, label=body[3], iface=body[4], action=body[6], dir=body[7], src=body[18], dst=body[19],
                       sport=sport, dport=int(body[21]), line=line))
    if not a.offline:
        with open(fwf, 'w') as fh:
            fh.write('\n'.join(x['line'] for x in fw) + '\n')

    # 4. matching
    res = []
    # Authentication: per (host, user, event id) key, captured = min(found, expected), in time order
    want = defaultdict(list)
    for cid, g in gt.items():
        if g['Kind'] == 'auth':
            eid = 4624 if g['Outcome'] == 'Success' else 4625
            want[(g['Workstation'].upper(), g['User'].lower(), eid)].append(cid)
    have = defaultdict(int)
    for e in win:
        if e['id'] == 4625 or (e['id'] == 4624 and e['lt'] == '2'):
            have[(e['host'], e['user'], e['id'])] += 1
    for key, cids in want.items():
        found = have.get(key, 0)
        for i, cid in enumerate(sorted(cids, key=lambda c: gt[c]['TimestampUtc'])):
            res.append((cid, i < found, f'{key[2]} {key[0]} {key[1]}: {found} found / {len(cids)} expected'))
    # Authorization: Application 4100/4101 with case=<id> trial=<T> and the same decision
    for cid, g in gt.items():
        if g['Kind'] != 'pdp':
            continue
        eid = 4100 if g['Decision'] == 'Allow' else 4101
        hits = [e for e in app if e['id'] == eid and f'case={cid} ' in e['msg'] + ' ' and f'trial={t}' in e['msg']
                and f"decision={g['Decision']}" in e['msg']]
        res.append((cid, len(hits) >= 1, f'{eid} x{len(hits)}'))
    # Network: >= 1 filterlog line, direction in, expected action, exact 4-tuple
    for cid, g in gt.items():
        if g['Kind'] != 'net':
            continue
        act = 'pass' if g['Expected'] == 'Pass' else 'block'
        # exact 4-tuple AND within +-30 s of the attempt (OPNsense logs whole seconds; source ports repeat
        # if a trial is re-run, so the time check stops an old line from counting)
        when = iso(g['TimestampUtc'])
        m = [x for x in fw if x['dir'] == 'in' and x['src'] == g['SrcIp'] and x['sport'] == int(g['SrcPort'])
             and x['dst'] == g['DstIp'] and x['dport'] == int(g['DstPort'])
             and abs((dt.datetime.fromisoformat(x['time']) - when).total_seconds()) <= 30]
        ok = [x for x in m if x['action'] == act]
        other = [x for x in m if x['action'] != act]
        ev = f"{act} x{len(ok)} label={ok[0]['label'][:8] if ok else '-'}" + (f' UNEXPECTED {other[0]["action"]} x{len(other)}' if other else '')
        res.append((cid, len(ok) >= 1, ev))

    assert sorted(c for c, _, _ in res) == sorted(cases)
    outf = os.path.join(out, f's6-{t}-cases' + ('-negcontrol' if a.negcontrol else '-offline' if a.offline else '') + '.csv')
    with open(outf, 'w', newline='') as fh:
        wr = csv.writer(fh)
        wr.writerow(['CaseId', 'Family', 'Granted', 'Captured', 'Evidence', 'TimestampUtc'])
        for cid, cap, ev in sorted(res):
            c = cases[cid]; g = gt[cid]
            granted = {'auth': g.get('Outcome') == 'Success', 'pdp': g.get('Decision') == 'Allow', 'net': c['Granted'] == 'True'}[g['Kind']]
            wr.writerow([cid, c['Family'], granted, cap, ev, g['TimestampUtc']])
    summ = defaultdict(lambda: [0, 0])
    for cid, cap, _ in res:
        summ[cases[cid]['Family']][0] += cap; summ[cases[cid]['Family']][1] += 1
    total = sum(v[0] for v in summ.values())
    if a.negcontrol:
        missed = sorted(c for c, cap, _ in res if not cap)
        print(f'NEGATIVE CONTROL {t}: broke {broken}; reported missed {missed} -> ' + ('OK' if missed == sorted(broken) else 'FAILED'))
    print(f'S6 {t}{" (dry)" if a.dry else ""}{" (offline)" if a.offline else ""}: captured {total}/100 = {total}% | ' +
          ' '.join(f'{k} {v[0]}/{v[1]}' for k, v in sorted(summ.items())) + f' | window {w0:%H:%M:%S}-{w1:%H:%M:%S}Z')
    for cid, cap, ev in sorted(res):
        if not cap:
            print('  MISSED', cid, cases[cid]['Family'], gt[cid].get('User', gt[cid].get('DstIp', '')), ev)


if __name__ == '__main__':
    main()
