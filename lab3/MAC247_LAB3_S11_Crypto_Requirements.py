# MAC 247 Graded Lab 3, Session 11: what the data requires, and what the keys cost
# Tuesday, October 27, 2026. Kali Linux in B124, in the terminal.
#
# Run it from your lab3 folder, after token.txt exists there:
#
#     python3 MAC247_LAB3_S11_Crypto_Requirements.py | tee s11_output.txt
#
# It measures what a password-derived key costs on this machine, builds envelope encryption
# from the standard library, and writes the policy and the checker Thursday runs against the
# key hierarchy you build there.
#
# Python 3 standard library only, so nothing has to be installed; any figure is printed as
# text, and saved as a PNG as well if matplotlib happens to be installed.
#
# Nothing here contacts any host: the script reads and writes only files in the folder you
# run it from. If an assertion stops the run, read its message, fix the block it names, and
# run the script again.

##############################################################################
# ## Section 1. Your token

import hashlib, hmac, os, time, datetime, csv, io, json

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
# ## Section 2. What a password-derived key costs, measured
#
# A key derivation function is deliberately slow. That is its entire job: it makes each guess
# expensive for somebody working through a stolen hash file, while costing a legitimate user one
# barely noticeable pause at login.
#
# Choosing the iteration count by copying a number out of a blog post is how systems end up with a
# figure that was defensible in 2015. Choose it by measuring on the hardware you have and picking
# the largest count that fits the delay you are willing to impose.

PASSWORD = ('mac247-' + TOKEN).encode()
SALT = hashlib.sha256(TOKEN.encode()).digest()[:16]
COUNTS = [50_000, 100_000, 200_000, 400_000, 600_000]

timings = []
for n in COUNTS:
    t0 = time.perf_counter()
    hashlib.pbkdf2_hmac('sha256', PASSWORD, SALT, n)
    ms = (time.perf_counter() - t0) * 1000
    timings.append((n, ms))
    print(f'{n:8,d} iterations  {ms:8.1f} ms')

per_iter = timings[-1][1] / timings[-1][0]
BUDGET_MS = 250
chosen = max(10_000, int(BUDGET_MS / per_iter / 10_000) * 10_000)
print(f'\ncost per iteration      : {per_iter * 1000:.4f} microseconds')
print(f'budget                  : {BUDGET_MS} ms')
print(f'largest count that fits : {chosen:,d}')
assert timings[-1][1] > timings[0][1], 'more iterations must take longer'
assert chosen > 0
print('  CHECK PASS: the iteration count came from a measurement on this machine')

print(f'derivation cost on this machine, token {TOKEN}')
_top = max(m for _, m in timings) or 1
for n, m in timings:
    over = '   over the budget' if m > BUDGET_MS else ''
    print(f'  {n:>9,d} iterations {m:9.1f} ms  {"#" * max(1, int(round(40 * m / _top)))}{over}')
print(f'  budget {BUDGET_MS} ms')
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
    ns = [n for n, _ in timings]
    ms = [m for _, m in timings]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.plot(ns, ms, marker='o')
    ax.axhline(BUDGET_MS, linestyle='--', linewidth=1)
    ax.annotate(f'{BUDGET_MS} ms budget', (ns[0], BUDGET_MS), textcoords='offset points',
                xytext=(4, 6), fontsize=9)
    ax.set_xlabel('PBKDF2-HMAC-SHA256 iterations'); ax.set_ylabel('milliseconds')
    ax.set_title(f'derivation cost on this machine, token {TOKEN}')
    ax.grid(alpha=0.3); plt.tight_layout(); plt.savefig('chart_s11_cost.png', dpi=150); plt.close('all')
    print('figure saved: chart_s11_cost.png')
except ImportError:
    print('matplotlib is not installed here, so the text above is the figure.')
print('  CHECK PASS: the cost curve rendered')

##############################################################################
# ### The same number from the attacker's side
#
# The cost you accept at login is also the cost you impose on somebody guessing. Turn the
# measurement around: at the rate you just measured, how long does a dictionary of a given size
# take on one core. The answer is usually more sobering than the graph, and it is the argument for
# why the iteration count is not the only control.

DICTIONARY = 14_000_000        # a common leaked-password list, order of magnitude
sec = DICTIONARY * chosen * per_iter / 1000
print(f'{DICTIONARY:,d} candidates at {chosen:,d} iterations each')
print(f'  one core of this runtime : {sec / 3600:10.1f} hours')
print(f'  a rig 500 times faster   : {sec / 3600 / 500:10.2f} hours')
print('\nThe second line is why a key derivation function is a delay, not a defense. The')
print('defense is that the password was never in the list, which is a policy control.')

##############################################################################
# ## Section 3. Envelope encryption, built from the standard library
#
# Two keys, not one. A data encryption key protects the data. A key encryption key protects the
# data encryption key. Rotating the data key means re-encrypting the data; rotating the key
# encryption key means re-wrapping one small blob. That asymmetry is the whole reason the pattern
# exists, and it is the pattern behind every cloud key management service.
#
# The construction below uses HMAC-SHA256 as a key derivation function and as a keystream
# generator, and authenticates with a separate HMAC key. **It is a teaching construction.** It
# shows the shape of envelope encryption using only what the standard library gives you, and you
# would use a vetted authenticated cipher in anything real. On Thursday you build the same
# hierarchy with OpenSSL, which is the vetted implementation.

def hkdf(ikm, salt, info, length=32):
    """RFC 5869 extract-and-expand, SHA-256."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, block, counter = b'', b'', 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]

def keystream(key, nonce, nbytes):
    out, counter = b'', 0
    while len(out) < nbytes:
        out += hmac.new(key, nonce + counter.to_bytes(8, 'big'), hashlib.sha256).digest()
        counter += 1
    return out[:nbytes]

def seal(key, plaintext, aad=b''):
    """Encrypt then authenticate. Returns nonce || ciphertext || tag."""
    enc_k = hkdf(key, b'mac247-enc', b'encryption')
    mac_k = hkdf(key, b'mac247-mac', b'authentication')
    nonce = os.urandom(16)
    ct = bytes(a ^ b for a, b in zip(plaintext, keystream(enc_k, nonce, len(plaintext))))
    tag = hmac.new(mac_k, nonce + ct + aad, hashlib.sha256).digest()
    return nonce + ct + tag

def unseal(key, blob, aad=b''):
    enc_k = hkdf(key, b'mac247-enc', b'encryption')
    mac_k = hkdf(key, b'mac247-mac', b'authentication')
    nonce, ct, tag = blob[:16], blob[16:-32], blob[-32:]
    want = hmac.new(mac_k, nonce + ct + aad, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, want):
        raise ValueError('authentication failed: this blob was altered or the key is wrong')
    return bytes(a ^ b for a, b in zip(ct, keystream(enc_k, nonce, len(ct))))

##############################################################################
# ### Wrap, unwrap, and prove the round trip

KEK = hashlib.pbkdf2_hmac('sha256', PASSWORD, SALT, chosen)     # from the password, slowly
DEK = os.urandom(32)                                            # random, never from a password
record = f'MAC247 lab 3, student token {TOKEN}, sensitivity restricted\n'.encode()

wrapped_dek = seal(KEK, DEK, aad=b'dek-v1')
sealed_data = seal(DEK, record, aad=b'record-v1')

print(f'KEK          : {KEK.hex()[:32]}... (derived, {chosen:,d} iterations)')
print(f'DEK          : {DEK.hex()[:32]}... (random)')
print(f'wrapped DEK  : {len(wrapped_dek)} bytes')
print(f'sealed record: {len(sealed_data)} bytes for {len(record)} bytes of plaintext')

recovered_dek = unseal(KEK, wrapped_dek, aad=b'dek-v1')
assert recovered_dek == DEK
assert unseal(recovered_dek, sealed_data, aad=b'record-v1') == record
print('\n  CHECK PASS: the data key round-tripped through the key encryption key')

##############################################################################
# ### What the authentication tag is for
#
# Change one byte of the ciphertext and try to decrypt. Unauthenticated encryption would hand back
# a different plaintext and no warning at all. This construction refuses.

tampered = bytearray(sealed_data)
tampered[20] ^= 0x01
try:
    unseal(DEK, bytes(tampered), aad=b'record-v1')
    raise SystemExit('a tampered blob decrypted, which means the tag is not being checked')
except ValueError as exc:
    print('one flipped bit ->', exc)

wrong_aad = False
try:
    unseal(DEK, sealed_data, aad=b'record-v2')
except ValueError:
    wrong_aad = True
print('wrong associated data ->', 'refused' if wrong_aad else 'ACCEPTED, which is a bug')
assert wrong_aad
print('\n  CHECK PASS: the tag caught a flipped bit and a swapped context label')

##############################################################################
# ### Rotation, and what rotation does not do
#
# Rotating the data key means the data is re-encrypted under a new key. Two things are worth
# watching in the output: the ciphertext changes completely, and the old key stops working. The
# second is the point. A rotation after which the old key still opens the data is not a rotation,
# it is a second key.

DEK2 = os.urandom(32)
plain = unseal(DEK, sealed_data, aad=b'record-v1')
sealed_v2 = seal(DEK2, plain, aad=b'record-v1')
wrapped_dek2 = seal(KEK, DEK2, aad=b'dek-v2')

print(f'ciphertext before rotation: {sealed_data.hex()[:48]}...')
print(f'ciphertext after rotation : {sealed_v2.hex()[:48]}...')
assert sealed_v2 != sealed_data
assert unseal(DEK2, sealed_v2, aad=b'record-v1') == record

old_key_still_works = True
try:
    unseal(DEK, sealed_v2, aad=b'record-v1')
except ValueError:
    old_key_still_works = False
print(f'old data key opens the rotated blob: {old_key_still_works}')
assert not old_key_still_works
print('\n  CHECK PASS: rotation replaced the ciphertext and retired the old data key')
print('  token:', TOKEN)

##############################################################################
# ### Revocation and escrow, in one experiment
#
# Revoking a data key, when the data is encrypted under it and nothing else, is done by destroying
# the key. The data becomes unreadable, permanently, which is either exactly what you wanted or a
# catastrophe, depending entirely on whether an escrow copy existed first.

escrow_kek = hashlib.pbkdf2_hmac('sha256', b'escrow-officer-' + TOKEN.encode(), SALT, chosen)
escrowed = seal(escrow_kek, DEK2, aad=b'escrow-v1')          # deposit before destroying

del DEK2                                                      # the operational copy is gone
try:
    DEK2
    raise SystemExit('the key was not actually destroyed')
except NameError:
    print('operational copy of the data key: destroyed')

recovered = unseal(escrow_kek, escrowed, aad=b'escrow-v1')    # the escrow officer recovers it
assert unseal(recovered, sealed_v2, aad=b'record-v1') == record
print('escrow recovery          : the record is readable again')
print('\n  CHECK PASS: escrow recovered data that revocation had made unreadable')

##############################################################################
# ## Section 4. The policy Thursday has to satisfy
#
# Now put the pieces together into a statement about data rather than about keys. Four sensitivity
# levels, and for each one: whether encryption at rest is required, whether encryption in transit
# is required, the minimum symmetric key length, how often the data key rotates, and whether the
# key encryption key goes to escrow.
#
# The controls named in the last column are real entries in NIST SP 800-53 Rev 5: SC-12 covers key
# establishment and management, SC-13 covers the use of cryptography itself, and SC-28 covers
# protection of information at rest. Cite them by number in your report and check the numbers in
# the catalog rather than taking them from this script.

POLICY = [
    # level, at_rest, in_transit, min_key_bits, rotate_days, escrow, controls
    ('public',       'no',  'yes', 0,   0,   'no',  'SC-13'),
    ('internal',     'no',  'yes', 128, 730, 'no',  'SC-8 SC-13'),
    ('confidential', 'yes', 'yes', 256, 365, 'yes', 'SC-12 SC-13 SC-28'),
    ('restricted',   'yes', 'yes', 256, 90,  'yes', 'SC-12 SC-13 SC-28'),
]
HEAD = ['sensitivity', 'at_rest', 'in_transit', 'min_key_bits',
        'rotate_days', 'escrow', 'controls']

buf = io.StringIO()
w = csv.writer(buf)
w.writerow(HEAD)
for row in POLICY:
    w.writerow(row)
CRYPTO_POLICY_CSV = buf.getvalue()

print(f'{"level":14s} {"rest":5s} {"transit":8s} {"bits":>5s} {"rotate":>7s} {"escrow":7s} controls')
for lvl, rest, transit, bits, days, esc, ctrl in POLICY:
    print(f'{lvl:14s} {rest:5s} {transit:8s} {bits:5d} {days:7d} {esc:7s} {ctrl}')

levels = [r[0] for r in POLICY]
bits = [r[3] for r in POLICY]
days = [r[4] for r in POLICY if r[4]]
assert bits == sorted(bits), 'key length must not fall as sensitivity rises'
assert days == sorted(days, reverse=True), 'rotation must not slow as sensitivity rises'
print('\n  CHECK PASS: the policy is monotonic in sensitivity, both ways')

##############################################################################
# ### The checker Thursday runs
#
# On Thursday you build a real key hierarchy with OpenSSL and write a `keyring_manifest.csv`
# describing it. This checker reads that manifest against today's policy and says, row by row,
# whether the key you actually built meets the requirement for the data it protects. The last
# block writes `crypto_policy.csv` and `policy_check.py` into this folder for Thursday, and
# prints both as heredocs as well.

POLICY_CHECK_SRC = r'''
"""MAC 247 Lab 3: does the key hierarchy on this machine meet the policy?
Standard library only.   usage: python3 policy_check.py keyring_manifest.csv crypto_policy.csv
"""
import csv, sys

def load_policy(path):
    return {r['sensitivity']: r for r in csv.DictReader(open(path))}

def check(manifest_path, policy_path):
    pol = load_policy(policy_path)
    rows, failures = list(csv.DictReader(open(manifest_path))), 0
    print(f'{"key_id":16s} {"sensitivity":14s} {"bits":>5s} {"age":>4s} {"escrow":7s} verdict')
    for r in rows:
        p = pol.get(r['sensitivity'])
        if p is None:
            print(f'{r["key_id"]:16s} {r["sensitivity"]:14s} '
                  f'{"":5s} {"":4s} {"":7s} FAIL unknown sensitivity')
            failures += 1
            continue
        why = []
        if int(r['key_bits']) < int(p['min_key_bits']):
            why.append(f'key is {r["key_bits"]} bits, policy needs {p["min_key_bits"]}')
        if int(p['rotate_days']) and int(r['age_days']) > int(p['rotate_days']):
            why.append(f'age {r["age_days"]} days exceeds rotation {p["rotate_days"]}')
        if p['escrow'] == 'yes' and r['escrowed'] != 'yes':
            why.append('policy requires escrow and this key has none')
        failures += bool(why)
        print(f'{r["key_id"]:16s} {r["sensitivity"]:14s} {r["key_bits"]:>5s} '
              f'{r["age_days"]:>4s} {r["escrowed"]:7s} '
              f'{"PASS" if not why else "FAIL " + "; ".join(why)}')
    print(f'\n{len(rows)} keys checked, {failures} failing')
    return failures

if __name__ == '__main__':
    a = sys.argv[1] if len(sys.argv) > 1 else 'keyring_manifest.csv'
    b = sys.argv[2] if len(sys.argv) > 2 else 'crypto_policy.csv'
    raise SystemExit(1 if check(a, b) else 0)
'''

sample = ('key_id,sensitivity,key_bits,age_days,escrowed\n'
          'kek-001,restricted,256,3,yes\n'
          'dek-001,restricted,256,3,yes\n'
          'dek-old,confidential,128,400,no\n')
open('crypto_policy.csv', 'w').write(CRYPTO_POLICY_CSV)
open('sample_keyring_manifest.csv', 'w').write(sample)
ns = {'__name__': 'checker'}
exec(POLICY_CHECK_SRC, ns)
fails = ns['check']('sample_keyring_manifest.csv', 'crypto_policy.csv')
assert fails == 1, 'the deliberately bad row should be the only failure'
print('\n  CHECK PASS: the checker passed two good keys and failed the stale 128-bit one')

print("cat > crypto_policy.csv <<'CSV'")
print(CRYPTO_POLICY_CSV.strip())
print('CSV')
print()
print("cat > policy_check.py <<'PY'")
print(POLICY_CHECK_SRC.strip())
print('PY')
print(f'# token {TOKEN}')
open('crypto_policy.csv', 'w').write(CRYPTO_POLICY_CSV.strip() + '\n')
open('policy_check.py', 'w').write(POLICY_CHECK_SRC.strip() + '\n')
print('# crypto_policy.csv and policy_check.py have been written to this folder as well.')

##############################################################################
# ## Closing this session
#
# All the CHECK PASS lines must appear in s11_output.txt. Then:
#
# 1. Screenshots, each showing your username and your token: `lab3_s11_kdf_cost.png`, the timing table and the cost curve; and `lab3_s11_envelope.png`, the round trip, the tamper refusal and the rotation output.
# 2. At minute 45, in the lab3 folder: cat token.txt, then git add -A,
#    git commit -m "lab3 session 11", git push.
# 3. Sign out: gh auth logout, or git credential-cache exit and delete the token on GitHub,
#    and capture lab3_s11_logout.png with the token and the sign-out confirmation.
# 4. Open the commit on github.com and confirm the script, its output and your screenshots are there.
#
# ## What goes in the report
#
# 1. Your measured cost per iteration and the count you chose for a 250 millisecond budget. Then
#    say what you would choose for a server handling two hundred logins a second, and why the
#    answer is different.
# 2. Explain, in terms of what has to be re-encrypted, why rotating the key encryption key is cheap
#    and rotating the data encryption key is not.
# 3. The tamper test failed closed. Describe what an unauthenticated stream cipher would have
#    returned instead, and name one situation where a system acting on that returned value would be
#    worse than the system simply stopping.
# 4. Escrow recovered data that revocation had destroyed. Give one argument for holding an escrow
#    copy and one argument against, and say who in an organization should hold it if it exists.
# 5. Your policy table, with the SP 800-53 Rev 5 control numbers checked against the catalog rather
#    than copied from this script. If you find one that does not say what this script implies,
#    say so; that finding is worth more than agreement.
