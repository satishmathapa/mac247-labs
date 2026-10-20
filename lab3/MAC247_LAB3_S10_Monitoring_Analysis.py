# MAC 247 Graded Lab 3, Session 10: monitoring results, and what a rule is worth
# Tuesday, October 20, 2026. Kali Linux in B124, in the terminal.
#
# Run it from your lab3 folder, after token.txt exists there:
#
#     python3 MAC247_LAB3_S10_Monitoring_Analysis.py | tee s10_output.txt
#
# It reads the auth.log, http_access.log, firewall.log and ground_truth.json that Thursday's
# session wrote into this folder, merges three formats into one event record, and measures
# four detection rules against the ground truth, so that a rule comes with its own evidence.
#
# Python 3 standard library only, so nothing has to be installed; any figure is printed as
# text, and saved as a PNG as well if matplotlib happens to be installed.
#
# Nothing here contacts any host: the script reads and writes only files in the folder you
# run it from. If an assertion stops the run, read its message, fix the block it names, and
# run the script again.

##############################################################################
# ## Section 1. Your token

import hashlib, datetime, re, json, collections, io

import pathlib
# The token for this lab lives in token.txt in your lab folder. The lab's first session creates it
# with the two shell lines in the lab document, and every later session reads the same file.
_token_file = pathlib.Path('token.txt')
if _token_file.exists():
    TOKEN = _token_file.read_text().split()[-1]
else:
    sid = 'YOUR_STUDENT_ID'          # used only if token.txt is missing
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M')
    TOKEN = hashlib.sha256((sid + '-' + stamp).encode()).hexdigest()[:16]
    print('token.txt was not found here: run this script from your lab folder after creating it')
print('MAC247 Lab 3 token:', TOKEN)

##############################################################################
# ## Section 2. Where the data came from
#
# This is the generator you ran on Thursday, reproduced here so that nothing about the data is
# hidden from you. Read it before you analyze its output. Two things in it matter for the rest of
# the session: every address is from a documentation range, RFC 5737 and RFC 1918, so nothing here
# corresponds to a real host anywhere; and the script writes down which addresses are hostile at
# the same moment it writes the lines, which is what makes the scoring later honest.
#
# The script is also the answer to a question worth asking out loud: why not analyze a real
# capture? Because a real capture is somebody's traffic. Synthetic data you generated yourself is
# the only kind you can commit to a public-facing repository without a second thought.

#!/usr/bin/env python3
"""MAC 247 Graded Lab 3: generate the three log files this lab analyzes.

Standard library only. Runs anywhere Python 3 does. Nothing is captured from any
network: every line below is written by this script from its own seed, so the
data is synthetic, yours alone, and safe to commit.

    python3 mac247_lab3_make_logs.py YOUR_TOKEN [outdir]

Writes auth.log, http_access.log, firewall.log and ground_truth.json.
"""
import hashlib, json, os, random, sys

DAY, HOST = 'Oct 15', 'kali'
BENIGN_USERS = ['student', 'analyst', 'backup']
WEB_OK = ['/', '/index.html', '/css/site.css', '/img/logo.png', '/api/status']
WEB_PROBE = ['/admin/config.php', '/.env', '/wp-login.php', '/cgi-bin/../../etc/passwd',
             '/phpmyadmin/', '/.git/config']
AGENTS = ['Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/140.0',
          'curl/8.14.1', 'python-requests/2.32.3']


def build(token, outdir='.'):
    seed = int(hashlib.sha256(('mac247-lab3-' + token).encode()).hexdigest()[:12], 16)
    rnd = random.Random(seed)
    # Documentation ranges only: RFC 5737 TEST-NET-2 and TEST-NET-3, and RFC 1918.
    loud = f'198.51.100.{20 + seed % 60}'          # noisy brute force, then web, then denied
    quiet = f'203.0.113.{10 + (seed // 7) % 60}'   # low and slow, three failures only
    decoy = f'10.0.2.{40 + (seed // 13) % 40}'     # highest volume in the logs, and benign
    benign = [f'10.0.2.{n}' for n in (11, 12, 13, 14)]
    while decoy in benign:
        decoy = f'10.0.2.{40 + rnd.randrange(40)}'

    auth, http, fw, t = [], [], [], 0

    def clock(step=None):
        nonlocal t
        t += rnd.randint(1, 4) if step is None else step
        return f'{DAY} {18 + t // 3600:02d}:{(t // 60) % 60:02d}:{t % 60:02d}'

    def hit(ip, path, code, agent):
        http.append(f'{ip} - - [15/Oct/2026:{clock(0)[7:]} +0000] "GET {path} HTTP/1.1" '
                    f'{code} {rnd.randint(180, 4096)} "-" "{agent}"')

    for i in range(18):                             # ordinary background traffic
        ip = benign[i % len(benign)]                # every benign host appears in the web log
        clock()
        if rnd.random() < 0.35:
            u = rnd.choice(BENIGN_USERS)
            auth.append(f'{clock(0)} {HOST} sshd[{rnd.randrange(2000, 9000)}]: '
                        f'Accepted publickey for {u} from {ip} port '
                        f'{rnd.randrange(40000, 60000)} ssh2: ED25519 SHA256:'
                        + hashlib.sha256(f'{ip}{i}'.encode()).hexdigest()[:22])
        hit(ip, rnd.choice(WEB_OK), 200, AGENTS[0])

    for i in range(24):                             # the decoy: heavy, dull, harmless
        clock(rnd.randint(0, 2))
        hit(decoy, rnd.choice(WEB_OK), 200, AGENTS[0])

    for ip, n in ((benign[0], 2), (benign[2], 1)):  # people mistype their own passwords
        for _ in range(n):
            clock(rnd.randint(4, 25))
            auth.append(f'{clock(0)} {HOST} sshd[{rnd.randrange(2000, 9000)}]: Failed '
                        f'password for {rnd.choice(BENIGN_USERS)} from {ip} port '
                        f'{rnd.randrange(40000, 60000)} ssh2')

    port = rnd.randrange(50000, 60000)              # stage 1, the loud brute force
    for i in range(11):
        clock(rnd.randint(1, 5))
        user = 'root' if i % 2 else rnd.choice(['admin', 'oracle', 'test'])
        auth.append(f'{clock(0)} {HOST} sshd[{port}]: Failed password for '
                    f'{"" if user == "root" else "invalid user "}{user} from {loud} '
                    f'port {port + i} ssh2')
    auth.append(f'{clock(20)} {HOST} sshd[{port}]: error: maximum authentication attempts '
                f'exceeded for root from {loud} port {port} ssh2 [preauth]')

    for i in range(3):                              # stage 2, the same host probes the web app
        clock(rnd.randint(2, 9))
        hit(loud, WEB_PROBE[i % len(WEB_PROBE)], rnd.choice([404, 403, 404]), AGENTS[1])

    for dport in (5432, 3306, 445):                 # stage 3, and the firewall stops it
        clock(rnd.randint(3, 12))
        fw.append(f'{clock(0)} {HOST} kernel: MAC247-DENY IN=eth0 OUT= SRC={loud} '
                  f'DST=10.0.2.15 PROTO=TCP SPT={port} DPT={dport}')

    for i in range(3):                              # the quiet one, spread out, no burst
        clock(rnd.randint(300, 520))
        auth.append(f'{clock(0)} {HOST} sshd[{rnd.randrange(2000, 9000)}]: Failed password '
                    f'for invalid user svc from {quiet} port {rnd.randrange(40000, 60000)} ssh2')
    clock(60)
    hit(quiet, WEB_PROBE[-1], 404, AGENTS[2])
    fw.append(f'{clock(30)} {HOST} kernel: MAC247-DENY IN=eth0 OUT= SRC={quiet} '
              f'DST=10.0.2.15 PROTO=TCP SPT=44321 DPT=22')

    # Benign hosts trip the firewall too, on ordinary service discovery. Two of them are
    # the same hosts that mistyped a password above, so a rule that only asks whether an
    # address appears in all three logs will flag them. That is the point of including them.
    for ip in (benign[0], benign[1], benign[2], benign[0]):
        clock(rnd.randint(5, 40))
        fw.append(f'{clock(0)} {HOST} kernel: MAC247-DENY IN=eth0 OUT= '
                  f'SRC={ip} DST=239.255.255.250 PROTO=UDP '
                  f'SPT={rnd.randrange(30000, 60000)} DPT=1900')

    truth = {'token': token, 'malicious': sorted([loud, quiet]),
             'benign': sorted(benign + [decoy]),
             'decoy_high_volume_benign': decoy,
             'notes': 'loud = ssh brute force then web probe then firewall deny; '
                      'quiet = three spread-out ssh failures; decoy = most requests, benign'}

    os.makedirs(outdir, exist_ok=True)
    for name, lines in (('auth.log', auth), ('http_access.log', http), ('firewall.log', fw)):
        with open(os.path.join(outdir, name), 'w') as fh:
            fh.write('\n'.join(lines) + '\n')
    with open(os.path.join(outdir, 'ground_truth.json'), 'w') as fh:
        json.dump(truth, fh, indent=2)
    return {'auth.log': len(auth), 'http_access.log': len(http),
            'firewall.log': len(fw), 'ground_truth': truth}
print('generator loaded; build(token, outdir) writes the four files')

##############################################################################
# ## Section 3. Loading Thursday's logs
#
# The next block reads `auth.log`, `http_access.log`, `firewall.log` and `ground_truth.json`
# from this folder, where Thursday's session left them. If they are missing, the script
# regenerates an equivalent set in a `regen` folder with today's token, so the code still runs
# and your own files are never touched. Say in your report which path you used; the graded run
# is the one that loads the files your Thursday session produced.

import os
UPLOADED = {}
for name in ('auth.log', 'http_access.log', 'firewall.log', 'ground_truth.json'):
    if os.path.exists(name):
        UPLOADED[name] = open(name, 'rb').read()
print('files found in this folder:', sorted(UPLOADED) or 'none')

NEEDED = ['auth.log', 'http_access.log', 'firewall.log', 'ground_truth.json']
if all(n in UPLOADED for n in NEEDED):
    BLOBS = {n: UPLOADED[n].decode() for n in NEEDED}
    SOURCE = 'your Thursday export'
else:
    print('=' * 68)
    print('  Thursday files not found in this folder. Regenerating an equivalent set here.')
    print('  For the graded run, run this script in your lab3 folder, where Thursday left them.')
    print('=' * 68)
    build(TOKEN, 'regen')
    BLOBS = {n: open('regen/' + n).read() for n in NEEDED}
    SOURCE = 'regenerated by this script'

TRUTH = json.loads(BLOBS['ground_truth.json'])
MALICIOUS = set(TRUTH['malicious'])
print(f'\nloaded from {SOURCE}')
for n in NEEDED[:3]:
    print(f'  {n:18s} {len(BLOBS[n].strip().splitlines()):4d} lines')
print(f'  ground truth       {len(MALICIOUS)} hostile addresses, '
      f'{len(TRUTH["benign"])} benign')

##############################################################################
# ## Section 4. Three formats, one event record
#
# The three files are written by three different programs in three different formats and none of
# them was designed with your analysis in mind. That is the normal situation. Normalizing them into
# one record shape is not a chore before the real work, it *is* a large part of the real work, and
# the decisions you make here determine what you can ask later.
#
# One decision worth naming: the record keeps the source address, the time, the source file and a
# short description. It throws away the process identifier, the byte count and the user agent. Each
# of those could matter for some question; none of them matters for the questions below.

Event = collections.namedtuple('Event', 'time ip source kind detail')

def parse_syslog_time(prefix):
    return datetime.datetime.strptime('2026 ' + prefix, '%Y %b %d %H:%M:%S')

def parse_auth(blob):
    out = []
    for line in blob.splitlines():
        m = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
        if not m:
            continue
        kind = ('auth_fail' if 'Failed password' in line else
                'auth_maxtries' if 'maximum authentication attempts' in line else
                'auth_ok' if 'Accepted' in line else 'auth_other')
        out.append(Event(parse_syslog_time(line[:15]), m.group(1), 'auth', kind, line.strip()))
    return out

def parse_http(blob):
    out = []
    pat = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d{3})')
    for line in blob.splitlines():
        m = pat.match(line)
        if not m:
            continue
        ip, when, _verb, path, code = m.groups()
        t = datetime.datetime.strptime(when.split()[0], '%d/%b/%Y:%H:%M:%S')
        kind = 'http_4xx' if code.startswith('4') else 'http_ok'
        out.append(Event(t, ip, 'http', kind, f'{code} {path}'))
    return out

def parse_fw(blob):
    out = []
    for line in blob.splitlines():
        m = re.search(r'SRC=(\S+).*DPT=(\d+)', line)
        if not m:
            continue
        out.append(Event(parse_syslog_time(line[:15]), m.group(1), 'firewall',
                         'fw_deny', f'denied to port {m.group(2)}'))
    return out

EVENTS = sorted(parse_auth(BLOBS['auth.log']) + parse_http(BLOBS['http_access.log'])
                + parse_fw(BLOBS['firewall.log']), key=lambda e: e.time)
by_ip = collections.defaultdict(list)
for e in EVENTS:
    by_ip[e.ip].append(e)

print(f'{len(EVENTS)} events from {len(by_ip)} addresses across 3 sources\n')
print(f'{"address":16s} {"events":>6s}  {"sources":22s} kinds')
for ip, evs in sorted(by_ip.items(), key=lambda kv: -len(kv[1])):
    srcs = sorted({e.source for e in evs})
    kinds = sorted({e.kind for e in evs})
    print(f'{ip:16s} {len(evs):6d}  {",".join(srcs):22s} {",".join(kinds)}')
assert len(EVENTS) > 40, 'too few events parsed; check the log formats'
print('\n  CHECK PASS: three formats normalized into one record shape')
print('  token:', TOKEN)

##############################################################################
# ### The address with the most events is not the problem
#
# Look at the top of that table. The busiest address in your logs is almost certainly a benign one,
# and it is there on purpose. Counting events per address is the first analysis everyone writes and
# it is close to useless, because volume is a property of what a host does for a living, not of
# whether it means you harm.

busiest = max(by_ip.items(), key=lambda kv: len(kv[1]))[0]
print(f'busiest address      : {busiest} with {len(by_ip[busiest])} events')
print(f'is it hostile        : {busiest in MALICIOUS}')
print(f'actually hostile     : {sorted(MALICIOUS)}')
for ip in sorted(MALICIOUS):
    print(f'  {ip:16s} {len(by_ip.get(ip, [])):3d} events, '
          f'rank {sorted(by_ip, key=lambda k: -len(by_ip[k])).index(ip) + 1} by volume')
print('\n  CHECK PASS: volume ranking located, and it does not answer the question')

##############################################################################
# ## Section 5. The timeline
#
# For one hostile address, put every event from every source on one line in time order. This is the
# artifact an incident report is built from, and it is the first moment the three files stop being
# three files and become one story.

target = sorted(MALICIOUS, key=lambda ip: -len(by_ip.get(ip, [])))[0]
print(f'timeline for {target}, token {TOKEN}\n')
first = by_ip[target][0].time
for e in by_ip[target]:
    offset = int((e.time - first).total_seconds())
    print(f'  +{offset:5d}s  {e.source:9s} {e.kind:14s} {e.detail[:72]}')
stages = [e.source for e in by_ip[target]]
assert stages.index('auth') < stages.index('firewall'), \
    'the chain should begin in the authentication log'
print('\n  CHECK PASS: the chain runs authentication, then web, then firewall')

##############################################################################
# ## Section 6. Four rules, and what each one is worth
#
# Precision asks: of the addresses this rule flagged, what fraction deserved it. Recall asks: of
# the addresses that deserved flagging, what fraction did it catch. They pull against each other,
# and an analyst who reports one without the other is reporting half a result.
#
# The four rules below get harder in the right way. Read each before you run the block and write
# down your guess.

def window_burst(times, n, seconds):
    times = sorted(times)
    return any(sum(1 for t in times if 0 <= (t - times[i]).total_seconds() <= seconds) > n
               for i in range(len(times)))

fails = {ip: [e.time for e in evs if e.kind == 'auth_fail'] for ip, evs in by_ip.items()}
fails = {ip: t for ip, t in fails.items() if t}
probes = {ip for ip, evs in by_ip.items() if any(e.kind == 'http_4xx' for e in evs)}
denied = {ip for ip, evs in by_ip.items() if any(e.kind == 'fw_deny' for e in evs)}
three  = {ip for ip, evs in by_ip.items() if len({e.source for e in evs}) == 3}

def chain(ip):
    evs = by_ip[ip]
    f = next((e.time for e in evs if e.kind == 'auth_fail'), None)
    p = next((e.time for e in evs if e.kind == 'http_4xx' and f and e.time >= f), None)
    d = next((e.time for e in evs if e.kind == 'fw_deny' and p and e.time >= p), None)
    return bool(f and p and d)

RULES = [
    ('A  more than 5 auth failures in 60s',
     {ip for ip, t in fails.items() if window_burst(t, 5, 60)}),
    ('B  any auth failure at all', set(fails)),
    ('C  seen in all three log sources', three),
    ('D  auth failure, then 4xx, then deny', {ip for ip in by_ip if chain(ip)}),
]

def score(flagged):
    tp, fp = len(flagged & MALICIOUS), len(flagged - MALICIOUS)
    fn = len(MALICIOUS - flagged)
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return tp, fp, fn, p, r, f1

print(f'{"rule":38s} {"TP":>3s} {"FP":>3s} {"FN":>3s} {"prec":>6s} {"rec":>6s} {"F1":>6s}')
RESULTS = []
for name, flagged in RULES:
    tp, fp, fn, p, r, f1 = score(flagged)
    RESULTS.append((name, flagged, p, r, f1))
    print(f'{name:38s} {tp:3d} {fp:3d} {fn:3d} {p:6.2f} {r:6.2f} {f1:6.2f}')

best = max(RESULTS, key=lambda x: x[4])
print(f'\nbest by F1: {best[0].strip()}')
assert RESULTS[0][2] == 1.0 and RESULTS[0][3] < 1.0, \
    'rule A should be precise and incomplete'
assert best[4] == 1.0, 'one rule should reach both perfect precision and perfect recall'
print('  CHECK PASS: a precise rule missed half, and only the ordered chain got both right')
print('  token:', TOKEN)

##############################################################################
# ### Why C and D disagree
#
# Rules C and D flag almost the same thing and score differently. C asks whether an address appears
# in all three logs. D asks whether it appears in all three *in the order that tells a story*:
# something failed to log in, then went looking for pages that are not there, then got stopped by
# the firewall.
#
# Ordinary hosts appear in all three logs all day. They mistype a password, they load a page, their
# media player sends a discovery packet the firewall drops. Nothing about that sequence is an
# attack, and a rule that cannot tell the difference will bury the two addresses that matter under
# every desktop on the segment.

c_only = RULES[2][1] - RULES[3][1]
print('flagged by C but not by D:', sorted(c_only) or 'none')
for ip in sorted(c_only):
    kinds = [f'{e.source}:{e.kind}' for e in by_ip[ip]]
    print(f'  {ip:16s} {len(by_ip[ip])} events -> {", ".join(sorted(set(kinds)))}')
    print(f'{"":18s} hostile in the ground truth: {ip in MALICIOUS}')
print('\n  CHECK PASS: the false positives of rule C are named, one address at a time')

##############################################################################
# ## Section 7. The picture, and the rule you would deploy

ips = sorted(by_ip, key=lambda k: -len(by_ip[k]))[:8]
kinds = ['auth_ok', 'auth_fail', 'http_ok', 'http_4xx', 'fw_deny']
print(f'events by address and kind, * marks hostile, token {TOKEN}')
print(f"  {'address':19s}" + ''.join(f'{k:>10s}' for k in kinds) + '   total')
for ip in ips:
    counts = [sum(1 for e in by_ip[ip] if e.kind == k) for k in kinds]
    print(f"  {ip + (' *' if ip in MALICIOUS else ''):19s}" + ''.join(f'{c:10d}' for c in counts)
          + f'{sum(counts):8d}')
print()
print(f'rule quality, token {TOKEN}')
for r in RESULTS:
    print(f"  {r[0][:30]:30s} precision {r[2]:4.2f} {'#' * int(round(r[2] * 20)):20s}"
          f"  recall {r[3]:4.2f} {'=' * int(round(r[3] * 20))}")
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.6))

    ips = sorted(by_ip, key=lambda k: -len(by_ip[k]))[:8]
    kinds = ['auth_ok', 'auth_fail', 'http_ok', 'http_4xx', 'fw_deny']
    bottom = np.zeros(len(ips))
    for k in kinds:
        vals = np.array([sum(1 for e in by_ip[ip] if e.kind == k) for ip in ips], dtype=float)
        ax1.bar(range(len(ips)), vals, bottom=bottom, label=k)
        bottom += vals
    ax1.set_xticks(range(len(ips)))
    ax1.set_xticklabels([ip + (' *' if ip in MALICIOUS else '') for ip in ips],
                        rotation=45, ha='right', fontsize=8)
    ax1.set_ylabel('events'); ax1.legend(fontsize=7)
    ax1.set_title('events by address and kind, * marks hostile')

    x = np.arange(len(RESULTS))
    ax2.bar(x - 0.2, [r[2] for r in RESULTS], 0.38, label='precision')
    ax2.bar(x + 0.2, [r[3] for r in RESULTS], 0.38, label='recall')
    ax2.set_xticks(x); ax2.set_xticklabels([r[0][:2] for r in RESULTS])
    ax2.set_ylim(0, 1.08); ax2.legend(); ax2.set_title(f'rule quality, token {TOKEN}')
    plt.tight_layout(); plt.savefig('chart_s10_monitoring.png', dpi=150); plt.close('all')
    print('figure saved: chart_s10_monitoring.png')
except ImportError:
    print('matplotlib is not installed here, so the text above is the figure.')
print('  CHECK PASS: both figures rendered')

##############################################################################
# ### Write the rule down the way it would be deployed
#
# A rule that lives in an analysis script is an observation. A rule that lives in a detection pipeline has
# a name, a description, a window, a threshold, a severity and, most importantly, a recorded
# expectation of how it will perform, so that the first person to see it fire at 3 AM knows whether
# to believe it.

name, flagged, p, r, f1 = best
yaml = f"""# MAC247 lab3 detection rule, token {TOKEN}
rule:
  id: mac247-{TOKEN[:6]}-chain
  name: authentication failure followed by web probing and a firewall denial
  sources: [auth.log, http_access.log, firewall.log]
  logic: >
    same source address produces an ssh authentication failure, then an HTTP
    response in the 4xx range, then a firewall denial, in that order
  window: 3600 seconds
  severity: high
  measured_on: {len(by_ip)} addresses, {len(MALICIOUS)} hostile
  expected_precision: {p:.2f}
  expected_recall: {r:.2f}
  expected_f1: {f1:.2f}
  tuning_note: >
    dropping the ordering requirement raises recall no further and costs
    {len(c_only)} false positives per {len(by_ip)} addresses observed
"""
print(yaml)
open('alert_rule.yaml', 'w').write(yaml)
print('  CHECK PASS: the deployable rule carries its own measured expectations')

##############################################################################
# ## Closing this session
#
# All the CHECK PASS lines must appear in s10_output.txt. Then:
#
# 1. Screenshots, each showing your username and your token: `lab3_s10_timeline.png`, the timeline for your hostile address; and `lab3_s10_rule_scores.png`, the four-rule table with precision and recall.
# 2. At minute 45, in the lab3 folder: cat token.txt, then git add -A,
#    git commit -m "lab3 session 10", git push.
# 3. Sign out: gh auth logout, or git credential-cache exit and delete the token on GitHub,
#    and capture lab3_s10_logout.png with the token and the sign-out confirmation.
# 4. Open the commit on github.com and confirm the script, its output and your screenshots are there.
#
# ## What goes in the report
#
# 1. Your four-rule table, with your own numbers, and one sentence per rule saying what it is
#    trading away.
# 2. The busiest address in your logs and whether it was hostile. Then the general statement: name
#    one kind of legitimate host that would always top a volume ranking, and say what an analyst
#    who tunes on volume ends up spending their week doing.
# 3. Your timeline, and the one sentence you would put at the top of an incident report.
# 4. Rule D has perfect precision and perfect recall on this data set and would not keep either in
#    production. Give two concrete reasons, at least one of which is about the data rather than the
#    rule.
