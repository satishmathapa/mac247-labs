# MAC 247 Graded Lab 2, Session 7: scoring a real inventory
# Tuesday, October 6, 2026. Kali Linux in B124, in the terminal.
#
# Run it from your lab2 folder, after token.txt exists there:
#
#     python3 MAC247_LAB2_S07_Risk_Register.py | tee s07_output.txt
#
# It reads Thursday's assets.csv, patch_candidates.csv and controls.csv from this folder and
# scores them with the model from session 5. Risk is comparative: a single asset's score means
# little, and what you need is the ranking, the total, and how much risk your existing controls
# actually remove, all of which are properties of the whole population.
#
# Python 3 standard library only. If matplotlib happens to be installed, the two figures are
# also saved as PNG files; either way they are printed as text.
#
# Nothing here contacts any host: the script reads and writes only files in the folder you
# run it from. If an assertion stops the run, read its message, fix the block it names, and
# run the script again.

##############################################################################
# ## Section 5. Token, and the model, kept in one place
#
# `SCORER_SRC` below is the entire model as source text. This script runs it to do today's
# analysis, and at the end it writes the same text to `score.py` for Thursday and prints it as
# well. Keeping one copy is the point: if today scored one way and Thursday's script scored
# another, the before-and-after comparison that this lab ends with would be meaningless.

import hashlib, datetime, csv, io, json

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
print('MAC247 Lab 2 token:', TOKEN)

SCORER_SRC = r'''
"""MAC 247 Lab 2 risk scorer. Standard library only, so it runs on Kali unchanged."""
import csv, sys

MOVES  = {'deterrent': 'likelihood', 'preventive': 'likelihood',
          'detective': 'impact', 'corrective': 'impact', 'compensating': 'either'}
EFFECT = {'deterrent': 0.90, 'preventive': 0.45, 'detective': 0.70,
          'corrective': 0.60, 'compensating': 0.80}
EXPOSURE_L = {'none': 1, 'loopback': 1, 'lan': 3, 'internet': 5}
CIA_I      = {'L': 1, 'M': 3, 'H': 5}

def likelihood(exposure, pending):
    band = 0 if pending == 0 else (1 if pending <= 5 else 2)
    return min(5, EXPOSURE_L[exposure] + band)

def impact(c, i, a):
    return max(CIA_I[c], CIA_I[i], CIA_I[a])

def inherent(row):
    return likelihood(row['exposure'], int(row['pending_updates'])) * \
           impact(row['confidentiality'], row['integrity'], row['availability'])

def residual(row, kinds):
    lk = float(likelihood(row['exposure'], int(row['pending_updates'])))
    im = float(impact(row['confidentiality'], row['integrity'], row['availability']))
    for k in kinds:
        t = MOVES[k]
        if t == 'likelihood':
            lk *= EFFECT[k]
        elif t == 'impact':
            im *= EFFECT[k]
        elif lk >= im:
            lk *= EFFECT[k]
        else:
            im *= EFFECT[k]
    return round(lk * im, 2)

def treatment(res):
    if res >= 12:  return 'mitigate'
    if res >= 6:   return 'transfer'
    if res >= 3:   return 'accept with review'
    return 'accept'

def register(assets_path='assets.csv', controls_path='controls.csv'):
    assets = list(csv.DictReader(open(assets_path)))
    by_asset = {}
    try:
        for c in csv.DictReader(open(controls_path)):
            by_asset.setdefault(c['asset_id'], []).append(c['control_kind'])
    except FileNotFoundError:
        pass
    out = []
    for a in assets:
        kinds = by_asset.get(a['asset_id'], [])
        inh, res = inherent(a), residual(a, kinds)
        out.append({'asset_id': a['asset_id'], 'name': a['name'],
                    'exposure': a['exposure'], 'pending': a['pending_updates'],
                    'controls': '+'.join(kinds) or 'none',
                    'inherent': inh, 'residual': res,
                    'treatment': treatment(res)})
    return sorted(out, key=lambda r: -r['residual'])

if __name__ == '__main__':
    rows = register(*(sys.argv[1:3] or []))
    print(f'{"asset":22s} {"exp":9s} {"controls":26s} {"inh":>5s} {"res":>7s}  treatment')
    for r in rows:
        print(f'{r["name"][:22]:22s} {r["exposure"]:9s} {r["controls"][:26]:26s} '
              f'{r["inherent"]:5d} {r["residual"]:7.2f}  {r["treatment"]}')
    ti = sum(r['inherent'] for r in rows)
    tr = sum(r['residual'] for r in rows)
    print(f'\ntotal inherent {ti:.2f}   total residual {tr:.2f}   '
          f'reduction {100 * (ti - tr) / ti:.1f} percent')
'''
ns = {}
exec(SCORER_SRC, ns)
register, inherent, residual, treatment = (ns['register'], ns['inherent'],
                                           ns['residual'], ns['treatment'])
print('scorer loaded,', len(SCORER_SRC.splitlines()), 'lines')

##############################################################################
# ## Section 6. Loading Thursday's inventory
#
# The next block reads `assets.csv`, `patch_candidates.csv` and `controls.csv` from this folder,
# where session 6 left them. If they are missing, the script says so in a banner and falls back
# to demonstration data, written to separate demo_ files so your own are never overwritten.
# **Demonstration data earns no marks.**

import os
UPLOADED = {}
for name in ('assets.csv', 'patch_candidates.csv', 'controls.csv'):
    if os.path.exists(name):
        UPLOADED[name] = open(name, 'rb').read()
print('files found in this folder:', sorted(UPLOADED) or 'none')

DEMO_ASSETS = '''asset_id,kind,name,version,exposure,confidentiality,integrity,availability,pending_updates
a01,service,ssh,9.9p1,lan,H,H,M,3
a02,service,postgresql,17.4,loopback,H,H,H,0
a03,service,cups-browsed,2.4.11,lan,L,M,L,8
a04,package,openssl,3.5.1,none,H,H,M,2
a05,package,curl,8.14.1,none,M,H,L,1
a06,filesystem,/home,ext4,none,H,H,M,0
a07,interface,eth0,-,lan,M,H,H,0
'''
DEMO_PATCH = '''package,installed,candidate,origin
openssl,3.5.0-1,3.5.1-1,kali-rolling
curl,8.14.0-1,8.14.1-1,kali-rolling
cups-browsed,2.4.10-2,2.4.11-1,kali-rolling
'''
DEMO_CONTROLS = '''asset_id,control_id,control_kind,description
a01,C-01,preventive,"key-only authentication, PasswordAuthentication no"
a01,C-02,detective,failed authentication logged to journald
a02,C-03,preventive,listens on 127.0.0.1 only
a03,C-04,deterrent,login banner on the print server
a06,C-05,corrective,nightly restore test of the home directory backup
a07,C-06,compensating,"daily interface review, the switch cannot do port security"
'''

def take(name, demo):
    if name in UPLOADED:
        return UPLOADED[name].decode(), True
    return demo, False

a_blob, a_real = take('assets.csv', DEMO_ASSETS)
p_blob, p_real = take('patch_candidates.csv', DEMO_PATCH)
c_blob, c_real = take('controls.csv', DEMO_CONTROLS)
REAL = a_real and c_real
if not REAL:
    print('=' * 66)
    print('  DEMONSTRATION DATA IN USE. THIS RUN EARNS NO MARKS.')
    print('  Run this script from your lab2 folder, where Thursday left its export.')
    print('=' * 66)

ASSETS_PATH, CONTROLS_PATH = 'assets.csv', 'controls.csv'
if not REAL:
    # Never overwrite your own files with demonstration data.
    ASSETS_PATH, CONTROLS_PATH = 'demo_assets.csv', 'demo_controls.csv'
    for n, b in ((ASSETS_PATH, a_blob), (CONTROLS_PATH, c_blob)):
        open(n, 'w').write(b)
patches = list(csv.DictReader(io.StringIO(p_blob)))
print(f'assets file: {"yours" if a_real else "demo"}   '
      f'controls file: {"yours" if c_real else "demo"}   '
      f'patch candidates: {len(patches)}')

##############################################################################
# ### The register
#
# One row per asset, sorted by residual risk. The two columns to read together are `controls` and
# the gap between `inh` and `res`: an asset with no controls has no gap, and an asset with a long
# control list and a small gap is running controls that do not move the term that matters.

ROWS = register(ASSETS_PATH, CONTROLS_PATH)
print(f'{"asset":22s} {"exp":9s} {"controls":26s} {"inh":>5s} {"res":>7s}  treatment')
for r in ROWS:
    print(f'{r["name"][:22]:22s} {r["exposure"]:9s} {r["controls"][:26]:26s} '
          f'{r["inherent"]:5d} {r["residual"]:7.2f}  {r["treatment"]}')

TI = sum(r['inherent'] for r in ROWS)
TR = sum(r['residual'] for r in ROWS)
print(f'\ntotal inherent {TI:.2f}   total residual {TR:.2f}   '
      f'reduction {100 * (TI - TR) / TI:.1f} percent')
assert TR <= TI, 'controls cannot increase total risk'
assert ROWS == sorted(ROWS, key=lambda r: -r['residual'])
print('  CHECK PASS: the register is ordered by residual risk and the total fell')
print('  token:', TOKEN)

##############################################################################
# ### Where the reduction came from
#
# A single percentage hides which controls earned it. Split the reduction by control kind: for each
# kind, score the population again with that kind removed and see how much the total goes up. That
# is the contribution of the kind, and it is the number that answers the question a budget holder
# asks, which is not how safe are we but what happens if I stop paying for this.

by_asset = {}
for c in csv.DictReader(io.StringIO(c_blob)):
    by_asset.setdefault(c['asset_id'], []).append(c['control_kind'])
assets = list(csv.DictReader(io.StringIO(a_blob)))

def total_residual(drop=None):
    return sum(residual(a, [k for k in by_asset.get(a['asset_id'], []) if k != drop])
               for a in assets)

baseline = total_residual()
contrib = {}
for kind in ('deterrent', 'preventive', 'detective', 'corrective', 'compensating'):
    contrib[kind] = round(total_residual(drop=kind) - baseline, 2)

print(f'{"control kind":15s} {"risk it removes":>16s}  {"instances":>9s}')
counts = {k: sum(v.count(k) for v in by_asset.values()) for k in contrib}
for k, v in sorted(contrib.items(), key=lambda kv: -kv[1]):
    print(f'{k:15s} {v:16.2f}  {counts[k]:9d}')
assert all(v >= 0 for v in contrib.values()), 'removing a control should not lower total risk'
print('\n  CHECK PASS: every control kind contributes a non-negative amount')

##############################################################################
# ### The picture
#
# Two charts. The first is the register as a bar pair so the gap between inherent and residual is
# visible rather than arithmetical. The second places every asset on likelihood against impact,
# which is the shape an executive risk report takes, and it shows something the table does not:
# which assets are high because of exposure and which are high because of what they hold.

top = ROWS[:8]
print(f'inherent against residual, top {len(top)} assets, token {TOKEN}')
for r in top:
    print(f"  {r['name'][:16]:16s} inherent {r['inherent']:6.2f} {'#' * int(round(r['inherent']))}")
    print(f"  {'':16s} residual {r['residual']:6.2f} {'=' * int(round(r['residual']))}")
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
    names = [r['name'][:16] for r in top]
    y = np.arange(len(top))
    fig, ax = plt.subplots(figsize=(8, 0.55 * len(top) + 1.4))
    ax.barh(y + 0.19, [r['inherent'] for r in top], height=0.36, label='inherent')
    ax.barh(y - 0.19, [r['residual'] for r in top], height=0.36, label='residual')
    ax.set_yticks(y); ax.set_yticklabels(names); ax.invert_yaxis()
    ax.set_xlabel('risk score'); ax.legend(loc='lower right')
    ax.set_title(f'MAC247 Lab 2 risk register, token {TOKEN}')
    plt.tight_layout(); plt.savefig('chart_s07_bars.png', dpi=150); plt.close(fig)
    print('figure saved: chart_s07_bars.png')
except ImportError:
    print('matplotlib is not installed here, so the text bars above are the figure.')

lk = ns['likelihood']; im = ns['impact']
points = [(a['name'][:14], lk(a['exposure'], int(a['pending_updates'])),
           im(a['confidentiality'], a['integrity'], a['availability'])) for a in assets]
print(f'likelihood against impact, token {TOKEN}  (each number is how many assets sit there)')
print('  impact')
for yv in range(5, 0, -1):
    row = ''
    for x in range(1, 6):
        here = sum(1 for _, px, py in points if px == x and py == yv)
        row += f'{here:^5d}' if here else '  .  '
    print(f'    {yv} |{row}')
print('      +' + '-' * 25)
print('       ' + ''.join(f'{x:^5d}' for x in range(1, 6)) + '  likelihood')
for n, px, py in sorted(points, key=lambda t: (-t[2], -t[1])):
    print(f'  {n:14s} likelihood {px}  impact {py}')
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(6.6, 5))
    for n, x, yv in points:
        ax.scatter(x, yv, s=90)
        ax.annotate(n, (x, yv), textcoords='offset points', xytext=(6, 5), fontsize=8)
    ax.set_xlim(0.5, 5.5); ax.set_ylim(0.5, 5.5)
    ax.set_xlabel('likelihood'); ax.set_ylabel('impact')
    ax.set_xticks(range(1, 6)); ax.set_yticks(range(1, 6))
    ax.grid(alpha=0.3)
    ax.set_title(f'likelihood against impact, token {TOKEN}')
    plt.tight_layout(); plt.savefig('chart_s07_matrix.png', dpi=150); plt.close(fig)
    print('figure saved: chart_s07_matrix.png')
except ImportError:
    print('matplotlib is not installed here, so the grid above is the figure.')
print('  CHECK PASS: both figures rendered')

##############################################################################
# ## Section 7. The treatment plan, and the scorer Thursday runs
#
# Four treatments and only four: mitigate, transfer, accept, avoid. Three of them appear in the
# register automatically from the residual score. The fourth, avoid, never appears automatically,
# because avoidance means not running the thing at all and no scoring function is entitled to make
# that decision for you.
#
# Pick the top three rows. For each, name the treatment, the specific change, and what you expect
# the residual score to become. On Thursday you make those changes on the machine, re-export, and
# run the scorer again. The prediction you write today is what makes Thursday a test rather than a
# demonstration.

print(f'# MAC247 lab2 treatment plan, token {TOKEN}\n')
for r in ROWS[:3]:
    print(f'asset       : {r["name"]} ({r["asset_id"]})')
    print(f'residual now: {r["residual"]:.2f}   suggested: {r["treatment"]}')
    print(f'exposure    : {r["exposure"]}, pending updates {r["pending"]}, '
          f'controls {r["controls"]}')
    print( 'your change :  ..................................................')
    print( 'predicted   :  ..................................................\n')
assert len(ROWS) >= 3, 'a register with fewer than three assets is not an inventory'
print('  CHECK PASS: three treatment candidates identified from the real ranking')

##############################################################################
# ### The scorer, for Thursday
#
# The last block writes the scorer to `score.py` in this folder and prints it as a heredoc too.
# On Thursday, run `python3 score.py` beside your re-exported `assets.csv` and `controls.csv`;
# if score.py has gone missing, paste the printed heredoc into the terminal instead.

print("cat > score.py <<'PY'")
print(SCORER_SRC.strip())
print('PY')
print()
print('# then, after your treatments and the re-export:')
print('python3 score.py assets.csv controls.csv | tee score_after.txt')
print(f'# token {TOKEN}')
open('score.py', 'w').write(SCORER_SRC.strip() + '\n')
print('# score.py has been written to this folder as well.')

##############################################################################
# ## Closing this session
#
# All the CHECK PASS lines must appear in s07_output.txt. Then:
#
# 1. Screenshots, each showing your username and your token: `lab2_s07_register.png`, the ranked register and the totals; and `lab2_s07_risk_matrix.png`, the likelihood against impact chart.
# 2. At minute 45, in the lab2 folder: cat token.txt, then git add -A,
#    git commit -m "lab2 session 7", git push.
# 3. Sign out: gh auth logout, or git credential-cache exit and delete the token on GitHub,
#    and capture lab2_s07_logout.png with the token and the sign-out confirmation.
# 4. Open the commit on github.com and confirm the script, its output and your screenshots are there.
#
# ## What goes in the report
#
# 1. Your ranked register, with your own asset names, and the total reduction percentage.
# 2. The contribution table. Name the control kind that removes the most risk in your population
#    and say whether that is because it is the most effective kind or because you happen to have
#    the most of them. The `instances` column is there so you can tell the difference.
# 3. Your three treatment rows, each with the change and the predicted residual, written before
#    Thursday.
# 4. One asset in your register sits high on impact and low on likelihood. Say what treatment that
#    combination argues for, and why mitigating likelihood further would be the wrong spend.
