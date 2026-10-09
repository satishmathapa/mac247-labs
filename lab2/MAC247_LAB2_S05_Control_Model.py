# MAC 247 Graded Lab 2, Session 5: the control taxonomy and the scoring model
# Tuesday, September 29, 2026. Kali Linux in B124, in the terminal.
#
# Run it from your lab2 folder, after token.txt exists there:
#
#     python3 MAC247_LAB2_S05_Control_Model.py | tee s05_output.txt
#
# Python 3 standard library only, so nothing has to be installed.
#
# Lab 2 starts on a Tuesday, so today builds the instrument before there is any real data:
# a classifier for the five kinds of security control, a risk scoring model that treats those
# five kinds differently, and the column layout that Thursday's export from this machine has
# to produce. A scoring model written after you have seen the findings is a model tuned to
# give the answer you already wanted, which is why it comes first.
#
# Nothing here contacts any host: the script reads and writes only files in the folder you
# run it from. If an assertion stops the run, read its message, fix the block it names, and
# run the script again.

##############################################################################
# ## Section 1. Your personalization token

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

##############################################################################
# ## Section 2. Five kinds of control, and what each one actually changes
#
# Textbooks list deterrent, preventive, detective, corrective and compensating and leave it there,
# which makes the list feel like vocabulary. It is not vocabulary. The five differ in *which term
# of the risk calculation they move*, and once you see that, classifying a control stops being a
# guess.
#
# | Kind | What it does | What it moves |
# |---|---|---|
# | Deterrent | Discourages a person from trying | Likelihood, weakly, and only against people who can be discouraged |
# | Preventive | Stops the act from succeeding | Likelihood, strongly |
# | Detective | Tells you it happened | Impact, by shortening the time before anyone responds |
# | Corrective | Restores the state afterwards | Impact, by shortening the time the loss persists |
# | Compensating | Stands in for a control you cannot deploy | Whatever the missing control would have moved, less well |
#
# A warning banner is deterrent. A firewall rule is preventive. A log alert is detective. A restore
# from backup is corrective. Reading the audit log daily *because* you cannot deploy multi-factor
# authentication on a legacy system is compensating, and it is compensating regardless of the fact
# that reading logs is otherwise detective. The kind depends on the job it is doing here.

CONTROL_KINDS = ('deterrent', 'preventive', 'detective', 'corrective', 'compensating')
MOVES = {'deterrent': 'likelihood', 'preventive': 'likelihood',
         'detective': 'impact', 'corrective': 'impact', 'compensating': 'either'}

# Teaching values. Each is the multiplier applied to the term the control moves.
# A value of 1.00 would mean the control changes nothing at all.
EFFECT = {'deterrent': 0.90, 'preventive': 0.45, 'detective': 0.70,
          'corrective': 0.60, 'compensating': 0.80}

for k in CONTROL_KINDS:
    print(f'{k:14s} moves {MOVES[k]:10s} by a factor of {EFFECT[k]:.2f}')

##############################################################################
# ### The classifier, and the case it is designed to get wrong
#
# Run the twelve cases below. Eleven are straightforward. One is the same mechanism in two
# different jobs, and it appears twice with two different answers on purpose.

CASES = [
    ('a sign reading this area is under video surveillance',            'deterrent'),
    ('a mantrap that admits one person per badge swipe',                'preventive'),
    ('an nftables rule dropping inbound traffic to port 5432',          'preventive'),
    ('an alert when one account fails six logins in a minute',          'detective'),
    ('a nightly restore test of last night backup',                     'corrective'),
    ('reimaging a workstation after a confirmed infection',             'corrective'),
    ('a login banner stating that use is monitored',                    'deterrent'),
    ('file integrity monitoring on /etc',                               'detective'),
    ('a quarterly access review that removes leftover group members',   'corrective'),
    ('multi-factor authentication on the administrator account',        'preventive'),
    ('reading the audit log daily, as routine monitoring',              'detective'),
    ('reading the audit log daily, because the vendor appliance cannot '
     'take multi-factor authentication and this is what stands in',     'compensating'),
]
for text, kind in CASES:
    assert kind in CONTROL_KINDS
    print(f'{kind:14s} {text}')
print('\n  CHECK PASS: twelve controls classified, including one mechanism in two roles')
print('  token:', TOKEN)

##############################################################################
# ## Section 3. The scoring model
#
# Inherent risk is what the asset carries before any control is credited. Residual risk is what is
# left after the controls that are actually in place, not the ones in the plan.
#
# Likelihood comes from two things the machine can tell you on Thursday: how exposed the asset is,
# and how far behind it is on patches. Impact comes from what the asset would cost you in each of
# confidentiality, integrity and availability, and the model takes the worst of the three, because
# an asset is as bad as its worst outcome, not its average one.

EXPOSURE_L = {'none': 1, 'loopback': 1, 'lan': 3, 'internet': 5}
PATCH_L    = {0: 0, 1: 1, 2: 2}          # pending security updates: none, some, many
CIA_I      = {'L': 1, 'M': 3, 'H': 5}

def likelihood(exposure, pending_security_updates):
    band = 0 if pending_security_updates == 0 else (1 if pending_security_updates <= 5 else 2)
    return min(5, EXPOSURE_L[exposure] + PATCH_L[band])

def impact(c, i, a):
    return max(CIA_I[c], CIA_I[i], CIA_I[a])

def inherent(exposure, pending, c, i, a):
    return likelihood(exposure, pending) * impact(c, i, a)

def residual(exposure, pending, c, i, a, controls):
    """controls is a list of control kinds already in place on this asset."""
    lk, im = float(likelihood(exposure, pending)), float(impact(c, i, a))
    for kind in controls:
        target = MOVES[kind]
        if target == 'likelihood':
            lk *= EFFECT[kind]
        elif target == 'impact':
            im *= EFFECT[kind]
        else:                                  # compensating, applied to the larger term
            if lk >= im:
                lk *= EFFECT[kind]
            else:
                im *= EFFECT[kind]
    return round(lk * im, 2)

##############################################################################
# ### Checking the model behaves the way the taxonomy says it should
#
# Four properties, each one a sentence from the table above turned into an assertion. If one fires,
# the model and the taxonomy disagree and one of them is wrong.

base = dict(exposure='lan', pending=7, c='H', i='H', a='M')
checks = [
    ('inherent risk is on the 1 to 25 scale',
     1 <= inherent(**base) <= 25),
    ('a preventive control beats a deterrent one on the same asset',
     residual(**base, controls=['preventive']) < residual(**base, controls=['deterrent'])),
    ('adding any control never raises residual risk',
     all(residual(**base, controls=[k]) <= inherent(**base) for k in CONTROL_KINDS)),
    ('internet exposure scores higher than loopback, everything else equal',
     inherent('internet', 7, 'H', 'H', 'M') > inherent('loopback', 7, 'H', 'H', 'M')),
]
for name, ok in checks:
    print(f'{"PASS" if ok else "FAIL"}  {name}')
assert all(ok for _, ok in checks), 'the model contradicts the taxonomy it claims to implement'
print(f'\ninherent for {base} = {inherent(**base)}')
for kind in CONTROL_KINDS:
    print(f'  residual with one {kind:13s} control = {residual(**base, controls=[kind]):6.2f}')
print('\n  CHECK PASS: the model behaves the way the five kinds say it should')

##############################################################################
# ### A control that is in the plan but not on the machine
#
# The model credits controls that are in place. The next block shows what the same asset scores
# when a preventive control is planned but not deployed, which is the single most common way a
# risk register ends up lying to the people who read it.

deployed = residual(**base, controls=['preventive', 'detective'])
planned  = residual(**base, controls=['detective'])
print(f'both controls deployed          : {deployed:6.2f}')
print(f'preventive still only planned   : {planned:6.2f}')
print(f'the difference the register hides: {planned - deployed:6.2f}')
assert planned > deployed
print('\n  CHECK PASS: crediting an undeployed control understates risk by a measurable amount')

##############################################################################
# ## Section 4. The schema Thursday's inventory must match
#
# Three files. Thursday's shell commands produce the first two straight out of the running system;
# you write the third yourself, because which controls are in place is a claim about the world that
# no command can answer for you.

SCHEMA = {
    'assets.csv': ['asset_id', 'kind', 'name', 'version', 'exposure',
                   'confidentiality', 'integrity', 'availability', 'pending_updates'],
    'patch_candidates.csv': ['package', 'installed', 'candidate', 'origin'],
    'controls.csv': ['asset_id', 'control_id', 'control_kind', 'description'],
    'vocabularies': {
        'kind': ['service', 'package', 'filesystem', 'interface'],
        'exposure': sorted(EXPOSURE_L),
        'cia': sorted(CIA_I),
        'control_kind': list(CONTROL_KINDS),
    },
}
print(json.dumps(SCHEMA, indent=2))

##############################################################################
# ### A dry run of the schema, with the validator Tuesday will use
#
# Same discipline as Lab 1: prove you can read the file before you ask a system to write it. The
# validator checks the header and the vocabularies, because a row reading exposure `external` is
# not a small problem, it is a row the scorer will crash on or, worse, silently skip.

def validate(name, blob):
    rows = list(csv.DictReader(io.StringIO(blob)))
    assert rows, f'{name} is empty'
    assert list(rows[0].keys()) == SCHEMA[name], (
        f'{name} header is {list(rows[0].keys())}, schema says {SCHEMA[name]}')
    vocab = SCHEMA['vocabularies']
    for n, r in enumerate(rows, start=2):
        for col, key in (('kind', 'kind'), ('exposure', 'exposure'),
                         ('control_kind', 'control_kind')):
            if col in r:
                assert r[col] in vocab[key], f'{name} line {n}: {col}={r[col]!r} not in vocabulary'
        for col in ('confidentiality', 'integrity', 'availability'):
            if col in r:
                assert r[col] in vocab['cia'], f'{name} line {n}: {col}={r[col]!r} not a CIA rating'
    return rows

good = ('asset_id,kind,name,version,exposure,confidentiality,integrity,availability,pending_updates\n'
        'a01,service,ssh,9.9p1,loopback,H,H,M,0\n'
        'a02,package,openssl,3.5.1,none,H,H,L,2\n')
bad = good.replace('loopback', 'external')

print('valid file  ->', len(validate('assets.csv', good)), 'rows accepted')
try:
    validate('assets.csv', bad)
    raise SystemExit('the validator accepted a bad vocabulary value')
except AssertionError as exc:
    print('invalid file->', exc)
print('\n  CHECK PASS: the validator accepts the schema and rejects an out-of-vocabulary value')
print('  token:', TOKEN)

##############################################################################
# ## Closing this session
#
# All the CHECK PASS lines must appear in s05_output.txt. Then:
#
# 1. Screenshots, each showing your username and your token: `lab2_s05_control_classes.png`, the twelve classified controls including the two log-reading rows; and `lab2_s05_model_checks.png`, the four PASS lines and the residual table.
# 2. At minute 45, in the lab2 folder: cat token.txt, then git add -A,
#    git commit -m "lab2 session 5", git push.
# 3. Sign out: gh auth logout, or git credential-cache exit and delete the token on GitHub,
#    and capture lab2_s05_logout.png with the token and the sign-out confirmation.
# 4. Open the commit on github.com and confirm the script, its output and your screenshots are there.
#
# ## What goes in the report
#
# 1. The two log-reading rows classify differently. Explain why, in terms of the job the control is
#    doing rather than the mechanism, and give one more pair of your own where the same mechanism
#    lands in two different kinds.
# 2. `EFFECT` gives preventive 0.45 and deterrent 0.90. Defend or attack those two numbers. If you
#    would change them, say what evidence would justify the change, because a number nobody can
#    argue with is a number nobody has checked.
# 3. The model takes the worst of confidentiality, integrity and availability rather than the
#    average. Name one asset where that choice is clearly right and one where it overstates the
#    risk.
# 4. Write down, before Thursday, which service on a stock Kali machine you expect to score highest
#    and why. You will find out whether you were right.
