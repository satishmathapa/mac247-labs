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
