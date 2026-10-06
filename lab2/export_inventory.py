"""Export this machine's assets, patch candidates, identities and entitlements."""
import csv, datetime, grp, pwd, re, subprocess

ROSTER = ['mac247_finlead', 'mac247_analyst', 'mac247_auditor', 'mac247_backup']

def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout

patches = []
for line in run('apt list --upgradable 2>/dev/null').splitlines():
    m = re.match(r'^([^/\s]+)/(\S+)\s+(\S+)\s+\S+\s+\[upgradable from: ([^\]]+)\]', line)
    if m:
        patches.append({'package': m.group(1), 'origin': m.group(2),
                        'candidate': m.group(3), 'installed': m.group(4)})

with open('patch_candidates.csv', 'w', newline='') as fh:
    w = csv.DictWriter(fh, ['package', 'installed', 'candidate', 'origin'])
    w.writeheader()
    w.writerows(patches)

pending_for = {p['package']: 1 for p in patches}
assets, seen = [], set()

for line in run('ss -ltnH').splitlines():
    parts = line.split()
    if len(parts) < 4:
        continue
    local = parts[3]
    port = local.rsplit(':', 1)[-1]
    addr = local.rsplit(':', 1)[0].strip('[]')
    exposure = 'loopback' if addr in ('127.0.0.1', '::1') else 'lan'
    if port in seen:
        continue
    seen.add(port)
    assets.append({'asset_id': f'a{len(assets)+1:02d}', 'kind': 'service',
                   'name': f'tcp/{port}', 'version': '-', 'exposure': exposure,
                   'confidentiality': 'M', 'integrity': 'M', 'availability': 'M',
                   'pending_updates': 0})

for pkg in ('openssl', 'curl', 'openssh-server', 'python3', 'sudo'):
    v = run(f"dpkg-query -W -f='${{Version}}' {pkg} 2>/dev/null").strip()
    if v:
        assets.append({'asset_id': f'a{len(assets)+1:02d}', 'kind': 'package',
                       'name': pkg, 'version': v, 'exposure': 'none',
                       'confidentiality': 'M', 'integrity': 'H',
                       'availability': 'L',
                       'pending_updates': pending_for.get(pkg, 0)})

with open('assets.csv', 'w', newline='') as fh:
    w = csv.DictWriter(fh, ['asset_id', 'kind', 'name', 'version', 'exposure',
                            'confidentiality', 'integrity', 'availability',
                            'pending_updates'])
    w.writeheader()
    w.writerows(assets)

def chage(user, field):
    for line in run(f'chage -l {user}').splitlines():
        if line.startswith(field):
            return line.split(':', 1)[1].strip()
    return ''

def iso(value):
    for fmt in ('%b %d, %Y', '%Y-%m-%d'):
        try:
            return datetime.datetime.strptime(value, fmt).date().isoformat()
        except ValueError:
            pass
    return value

ids = []
for u in ROSTER:
    try:
        p = pwd.getpwnam(u)
    except KeyError:
        continue
    st = run(f'passwd -S {u}').split()
    ids.append({'username': u, 'uid': p.pw_uid,
                'primary_group': grp.getgrgid(p.pw_gid).gr_name,
                'shell': p.pw_shell,
                'locked': 'yes' if len(st) > 1 and st[1] == 'L' else 'no',
                'last_change': iso(chage(u, 'Last password change'))})

with open('identities.csv', 'w', newline='') as fh:
    w = csv.DictWriter(fh, ['username', 'uid', 'primary_group', 'shell',
                            'locked', 'last_change'])
    w.writeheader()
    w.writerows(ids)

ents = []
for g in sorted(grp.getgrall(), key=lambda g: g.gr_name):
    if g.gr_name.startswith('mac247'):
        for m in sorted(g.gr_mem):
            if m in ROSTER:
                ents.append({'username': m,
                             'entitlement': 'group:' + g.gr_name,
                             'source': '/etc/group'})

with open('entitlements.csv', 'w', newline='') as fh:
    w = csv.DictWriter(fh, ['username', 'entitlement', 'source'])
    w.writeheader()
    w.writerows(ents)

print(f'{len(assets)} assets, {len(patches)} patch candidates, '
      f'{len(ids)} identities, {len(ents)} entitlement rows')
