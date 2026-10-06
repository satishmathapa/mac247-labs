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
