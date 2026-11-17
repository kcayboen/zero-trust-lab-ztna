#!/usr/bin/env python3
"""Generate the fixed S2 (RBAC) case file from the frozen policy matrix.

Usage: gen_cases.py [--out plan/cases/S2-rbac-cases.csv] [--n 100] [--seed 202]

Independent of the PDP: reads only plan/policy-matrix.csv; the role/zone tables
below are transcribed from plan/policy-matrix.md §2 (b)-(d). The Expected column
is therefore a second derivation of the policy, to be compared with the PDP's.
"""
import argparse, csv, os, random

SIM = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# policy-matrix.md §2 (a): role <- account
ACCOUNTS = {
    'Student': [f'student{i:02d}' for i in range(1, 11)],
    'Instructor': ['instructor01', 'instructor02', 'instructor03'],
    'ZTNA-Admin': ['admin-ztna01'],
}
# §2 (b): device/resource -> zone
ZONE = {'Student1': 'StudentWS', 'Student2': 'StudentWS', 'Instructor1': 'InstructorWS', 'DC01': 'Server'}
# §2 (c): permitted device zones per role
SIT = {'Student': {'StudentWS'}, 'Instructor': {'StudentWS', 'InstructorWS'},
       'ZTNA-Admin': {'StudentWS', 'InstructorWS', 'Server'}}
# §2 (d)
GLOBAL_DENY = {21, 23, 25, 69, 111, 1433, 3306, 5432}
PORTS = [445, 139, 3389, 5985, 53, 88, 389, 23]


def load_matrix(path):
    rows = []
    with open(path, newline='') as f:
        for r in csv.DictReader(f):
            rows.append((r['Role'], r['FromZone'], r['Target'], {int(p) for p in r['AllowedPorts'].split(';')}))
    return rows


def expected(matrix, role, device, resource, port):
    """Return (decision, rule) per policy-matrix.md §2 (c)-(f)."""
    dz = ZONE[device]
    if dz not in SIT[role]:
        return 'Deny', 'device-zone-not-permitted'
    if port in GLOBAL_DENY:
        return 'Deny', 'global-deny-port'
    target = 'Local' if resource == device else ZONE[resource]
    rows = [r for r in matrix if r[0] == role and r[2] == target and r[1] in (dz, '*')]
    # an exact FromZone row wins over '*'
    rows.sort(key=lambda r: r[1] == '*')
    if not rows:
        kind = 'peer-workstation' if target == dz else 'no-entry'
        return 'Deny', f'{kind}:{role}@{dz}->{target}'
    if port in rows[0][3]:
        return 'Allow', f'matrix:{role}@{rows[0][1]}->{target}'
    return 'Deny', f'port-not-permitted:{role}@{rows[0][1]}->{target}'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default=os.path.join(SIM, 'plan', 'cases', 'S2-rbac-cases.csv'))
    ap.add_argument('--n', type=int, default=100)
    ap.add_argument('--seed', type=int, default=202)
    a = ap.parse_args()
    matrix = load_matrix(os.path.join(SIM, 'plan', 'policy-matrix.csv'))

    space = []
    for role in ACCOUNTS:
        for device in ZONE:
            for resource in ZONE:
                for port in PORTS:
                    d, rule = expected(matrix, role, device, resource, port)
                    space.append(dict(role=role, device=device, resource=resource, port=port, exp=d, rule=rule))

    rng = random.Random(a.seed)
    allow = [c for c in space if c['exp'] == 'Allow']
    deny = [c for c in space if c['exp'] == 'Deny']
    n_allow = min(len(allow), a.n // 2)
    picked = rng.sample(allow, n_allow)
    # stratify denies by rule family so every denial path is exercised
    fams = {}
    for c in deny:
        fams.setdefault(c['rule'].split(':')[0], []).append(c)
    for v in fams.values():
        rng.shuffle(v)
    order = sorted(fams)
    while len(picked) < a.n:
        progressed = False
        for k in order:
            if fams[k] and len(picked) < a.n:
                picked.append(fams[k].pop())
                progressed = True
        if not progressed:
            break

    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    counters = {r: 0 for r in ACCOUNTS}
    with open(a.out, 'w', newline='') as f:
        w = csv.writer(f, lineterminator='\r\n')
        w.writerow(['CaseId', 'User', 'ExpectedRole', 'Device', 'DeviceZone', 'Resource', 'ResourceZone', 'Port', 'Expected', 'Rule'])
        for i, c in enumerate(sorted(picked, key=lambda c: (c['role'], c['device'], c['resource'], c['port'])), 1):
            accts = ACCOUNTS[c['role']]
            user = accts[counters[c['role']] % len(accts)]
            counters[c['role']] += 1
            w.writerow([f'S2-{i:03d}', user, c['role'], c['device'], ZONE[c['device']], c['resource'],
                        ZONE[c['resource']], c['port'], c['exp'], c['rule']])

    fam_count = {}
    for c in picked:
        k = c['exp'] + ' ' + c['rule'].split(':')[0]
        fam_count[k] = fam_count.get(k, 0) + 1
    print(f'space={len(space)} allow={len(allow)} deny={len(deny)} -> wrote {len(picked)} cases to {a.out}')
    for k in sorted(fam_count):
        print(f'  {fam_count[k]:3d}  {k}')


if __name__ == '__main__':
    main()
