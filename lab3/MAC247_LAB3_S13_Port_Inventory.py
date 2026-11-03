# MAC 247 Graded Lab 3, Session 13: from a scan result to a filtering policy
# Tuesday, November 3, 2026. Kali Linux in B124, in the terminal.
#
# Run it from your lab3 folder, after token.txt exists there:
#
#     python3 MAC247_LAB3_S13_Port_Inventory.py | tee s13_output.txt
#
# It reads the scan.xml your session 9 nmap run left in this folder, turns every open port
# into an inventory line with a decision on it, and writes the filtering policy and the test
# plan that Thursday loads and checks.
#
# Python 3 standard library only, so nothing has to be installed; any figure is printed as
# text, and saved as a PNG as well if matplotlib happens to be installed.
#
# Nothing here contacts any host: the script reads and writes only files in the folder you
# run it from. If an assertion stops the run, read its message, fix the block it names, and
# run the script again.

##############################################################################
# ## Section 1. Your token

import hashlib, datetime, csv, io, json
import xml.etree.ElementTree as ET

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
# ## Section 2. Loading your scan
#
# The next block reads `scan.xml` from this folder, the file your session 9
# `nmap -oX scan.xml 127.0.0.1` produced. If it is missing, the script falls back to a sample
# scan and says so. **The sample earns no marks**, because the whole point is that the
# inventory describes the machine you were sitting at.

import os
UPLOADED = {}
for name in ('scan.xml',):
    if os.path.exists(name):
        UPLOADED[name] = open(name, 'rb').read()
print('files found in this folder:', sorted(UPLOADED) or 'none')

SAMPLE_XML = '''<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -p- -oX scan.xml 127.0.0.1" version="7.95">
<host><status state="up" reason="localhost-response"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames><hostname name="localhost" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
  <service name="ssh" product="OpenSSH" version="10.0p2 Debian 5" method="probed" conf="10"/></port>
<port protocol="tcp" portid="631"><state state="open" reason="syn-ack"/>
  <service name="ipp" product="CUPS" version="2.4" method="probed" conf="10"/></port>
<port protocol="tcp" portid="3306"><state state="closed" reason="conn-refused"/>
  <service name="mysql" method="table" conf="3"/></port>
<port protocol="tcp" portid="8081"><state state="open" reason="syn-ack"/>
  <service name="blackice-icecap" method="table" conf="3"/></port>
<port protocol="tcp" portid="8082"><state state="open" reason="syn-ack"/>
  <service name="blackice-alerts" method="table" conf="3"/></port>
<port protocol="tcp" portid="8085"><state state="open" reason="syn-ack"/>
  <service name="unknown" method="table" conf="3"/></port>
</ports></host>
<runstats><finished elapsed="4.12"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
'''

if 'scan.xml' in UPLOADED:
    XML, REAL = UPLOADED['scan.xml'].decode(errors='replace'), True
else:
    print('=' * 66)
    print('  SAMPLE SCAN IN USE. THIS RUN EARNS NO MARKS.')
    print('  Run this script in your lab3 folder, where session 9 left scan.xml.')
    print('=' * 66)
    XML, REAL = SAMPLE_XML, False

##############################################################################
# ### Parsing it
#
# Three things the parser has to be careful about, and all three come up in real scans. A port can
# carry no `service` element at all. A `service` element can carry a name and no product or
# version. And a port that is `closed` or `filtered` is not the same as a port that is absent, so
# the parser keeps the state rather than keeping only the open ones.

root = ET.fromstring(XML)
PORTS = []
for host in root.findall('host'):
    addr = host.find('address').get('addr')
    for p in host.findall('./ports/port'):
        st = p.find('state')
        svc = p.find('service')
        PORTS.append({
            'address': addr,
            'protocol': p.get('protocol'),
            'port': int(p.get('portid')),
            'state': st.get('state') if st is not None else 'unknown',
            'service': (svc.get('name') if svc is not None else '') or 'unknown',
            'product': (svc.get('product') if svc is not None else '') or '',
            'version': (svc.get('version') if svc is not None else '') or '',
            'confidence': int(svc.get('conf')) if svc is not None and svc.get('conf') else 0,
            'method': (svc.get('method') if svc is not None else '') or '',
        })
PORTS.sort(key=lambda r: r['port'])

print(f'scan of {PORTS[0]["address"] if PORTS else "nothing"}, '
      f'{len(PORTS)} ports recorded\n')
print(f'{"port":>6s} {"state":9s} {"service":18s} {"conf":>4s} {"method":8s} product and version')
for r in PORTS:
    print(f'{r["port"]:6d} {r["state"]:9s} {r["service"]:18s} {r["confidence"]:4d} '
          f'{r["method"]:8s} {(r["product"] + " " + r["version"]).strip()}')
OPEN = [r for r in PORTS if r['state'] == 'open']
assert PORTS, 'no ports parsed; check that scan.xml is the -oX output and not the -oN output'
print(f'\n{len(OPEN)} open, {len(PORTS) - len(OPEN)} in another state')
print('  CHECK PASS: the machine-readable scan parsed, states and confidences intact')
print('  token:', TOKEN)

##############################################################################
# ### What the confidence column is telling you
#
# nmap reports how it decided. `method="table"` means it looked the port number up in
# `nmap-services` and reported what usually lives there, which is a guess dressed as a fact.
# `method="probed"` means it spoke to the service and the service answered. The confidence figure
# follows the same split.
#
# This matters for the report you write from a scan. A finding that reads *MySQL on 3306* when the
# method was `table` and nothing was listening is not a finding, it is a port number with a label
# attached. Separate the two before anybody acts on your output.

probed = [r for r in OPEN if r['method'] == 'probed']
guessed = [r for r in OPEN if r['method'] != 'probed']
print(f'identified by talking to the service : {len(probed)}')
for r in probed:
    print(f'   {r["port"]:6d} {r["service"]:16s} {(r["product"] + " " + r["version"]).strip()}')
print(f'\nlabelled from the port-number table  : {len(guessed)}')
for r in guessed:
    print(f'   {r["port"]:6d} {r["service"]:16s} (no banner; the name is a convention, not evidence)')
print('\n  CHECK PASS: the inventory separates what was observed from what was assumed')

##############################################################################
# ## Section 3. The port inventory, with a decision on every line
#
# An inventory without decisions is a list. For each open port, three questions: where it belongs
# in the TCP/IP model, who should be able to reach it, and what happens to traffic that is not on
# that list. The third is the only one that becomes a firewall rule, and it is the one people leave
# implicit.
#
# The classification below is deliberately conservative. Anything not recognized is
# `management` exposure `loopback`, because the safe default for something you cannot name is to
# let nothing reach it and find out what breaks.

KNOWN = {
    22:   ('ssh',        'application', 'management', 'lan',      'administrative access'),
    53:   ('domain',     'application', 'infrastructure', 'lan',  'name resolution'),
    80:   ('http',       'application', 'data',       'lan',      'cleartext web, see the note'),
    443:  ('https',      'application', 'data',       'lan',      'web over TLS'),
    631:  ('ipp',        'application', 'data',       'loopback', 'printing, rarely needs the network'),
    3306: ('mysql',      'application', 'data',       'loopback', 'database, application tier only'),
    5432: ('postgresql', 'application', 'data',       'loopback', 'database, application tier only'),
    5060: ('sip',        'application', 'voice',      'voice_vlan', 'converged voice signalling'),
}

def classify(r):
    if r['port'] in KNOWN:
        name, layer, plane, exposure, note = KNOWN[r['port']]
    else:
        name, layer, plane, exposure = r['service'], 'application', 'management', 'loopback'
        note = 'not recognized, so nothing is allowed to reach it'
    return {'port': r['port'], 'protocol': r['protocol'], 'service': name,
            'layer': layer, 'plane': plane, 'exposure': exposure, 'note': note,
            'evidence': 'probed' if r['method'] == 'probed' else 'assumed'}

INVENTORY = [classify(r) for r in OPEN]
print(f'{"port":>6s} {"service":16s} {"plane":14s} {"exposure":11s} {"evidence":9s} note')
for r in INVENTORY:
    print(f'{r["port"]:6d} {r["service"][:16]:16s} {r["plane"]:14s} {r["exposure"]:11s} '
          f'{r["evidence"]:9s} {r["note"]}')
assert all(r['exposure'] in ('lan', 'loopback', 'voice_vlan') for r in INVENTORY)
print('\n  CHECK PASS: every open port carries a plane, an exposure and the basis for its label')

##############################################################################
# ### Converged networks, and the rule that makes them safe
#
# A converged network carries voice, ordinary data and device management over the same physical
# plant. It is cheaper and it is standard, and the whole security argument for it rests on one
# property: the three planes are separated logically even though they share a wire. When they are
# not, a compromised desk phone is on the same segment as the switch management interface.
#
# Check your inventory against that rule. The block reports any place where two planes would end up
# reachable from the same source address range, which is the condition the separation is supposed
# to prevent.

by_exposure = {}
for r in INVENTORY:
    by_exposure.setdefault(r['exposure'], set()).add(r['plane'])

violations = []
for exposure, planes in sorted(by_exposure.items()):
    print(f'{exposure:12s} reachable planes: {", ".join(sorted(planes))}')
    if exposure != 'loopback' and len(planes) > 1:
        violations.append((exposure, sorted(planes)))

if violations:
    for exposure, planes in violations:
        print(f'\nSEPARATION BREAK: {exposure} reaches {planes[0]} and {planes[1]}, '
              f'so one compromised host on that range reaches both')
else:
    print('\nno plane is reachable from a range that also reaches another plane')
print('\n  CHECK PASS: the plane separation check ran over the real inventory')

##############################################################################
# ## Section 4. The filtering policy Thursday loads
#
# Now generate the rules. Three design decisions are baked in and you should be able to defend all
# three in the report.
#
# The table is named `mac247` and nothing else on the machine uses that name, so loading it cannot
# disturb rules that are already there and removing it is one command. The chain policy is
# `accept`, not `drop`, because a student loading a drop-by-default input chain onto a lab machine
# over a network session disconnects themselves, and a lab that bricks the machine teaches the
# wrong lesson at the wrong moment. And every rule matches `iif "lo"`, so the policy only ever
# applies to traffic the machine sends to itself, which is the only traffic you are authorized to
# filter.

DROP = [r for r in INVENTORY if r['exposure'] == 'loopback']
KEEP = [r for r in INVENTORY if r['exposure'] != 'loopback']

lines = [f'# MAC247 lab 3 filtering policy, generated in session 13, token {TOKEN}',
         '# loads into its own table so nothing already on the machine is disturbed',
         'table inet mac247 {',
         '  chain input {',
         '    type filter hook input priority 0; policy accept;']
for r in DROP:
    lines.append(f'    iif "lo" tcp dport {r["port"]} counter drop'
                 f'        # {r["service"]}: {r["note"]}')
for r in KEEP:
    lines.append(f'    iif "lo" tcp dport {r["port"]} counter accept'
                 f'      # {r["service"]}: reachable from {r["exposure"]}')
lines += ['  }', '}']
NFT = '\n'.join(lines) + '\n'
print(NFT)
assert 'policy accept' in NFT and NFT.count('iif "lo"') == len(INVENTORY)
print('  CHECK PASS: one rule per open port, all of them scoped to the loopback interface')

##############################################################################
# ### The test plan, written before the test
#
# For each open port, what you expect to happen on Thursday when you connect to it on loopback
# after the rules are loaded. Writing the expectation first is what turns Thursday into a test.
# A port you predicted would be dropped and that answers instantly is a finding, and you will only
# notice it if you wrote the prediction down.

buf = io.StringIO()
w = csv.writer(buf)
w.writerow(['port', 'service', 'exposure', 'expected_before_rules', 'expected_after_rules'])
for r in INVENTORY:
    after = 'timeout, no response' if r['exposure'] == 'loopback' else 'connects'
    w.writerow([r['port'], r['service'], r['exposure'], 'connects', after])
TESTPLAN = buf.getvalue()
print(TESTPLAN)
rows = list(csv.DictReader(io.StringIO(TESTPLAN)))
assert len(rows) == len(INVENTORY)
assert any(r['expected_after_rules'].startswith('timeout') for r in rows), \
    'a policy that drops nothing is not a policy'
print('  CHECK PASS: a prediction exists for every port, and at least one of them is a drop')
print('  token:', TOKEN)

##############################################################################
# ### For Thursday
#
# The last block writes the rules file and the test plan into this folder, as `nft_rules.conf`
# and `test_plan.csv`, and prints both as heredocs with the session 14 commands, in case either
# file goes missing.

print("cat > nft_rules.conf <<'NFT'")
print(NFT.strip())
print('NFT')
print()
print("cat > test_plan.csv <<'CSV'")
print(TESTPLAN.strip())
print('CSV')
print()
print('# then, in session 14, in this order:')
print('sudo nft -c -f nft_rules.conf      # check the syntax without loading anything')
print('sudo nft -f nft_rules.conf         # load it')
print('sudo nft list table inet mac247    # read back what the kernel actually holds')
print('#   ... run the connection tests ...')
print('sudo nft delete table inet mac247  # remove it before you leave')
print(f'# token {TOKEN}')
open('nft_rules.conf', 'w').write(NFT.strip() + '\n')
open('test_plan.csv', 'w').write(TESTPLAN.strip() + '\n')
print('# nft_rules.conf and test_plan.csv have been written to this folder as well.')

##############################################################################
# ## Closing this session
#
# All the CHECK PASS lines must appear in s13_output.txt. Then:
#
# 1. Screenshots, each showing your username and your token: `lab3_s13_port_inventory.png`, the inventory table with planes and exposures; and `lab3_s13_generated_rules.png`, the generated nftables policy.
# 2. At minute 45, in the lab3 folder: cat token.txt, then git add -A,
#    git commit -m "lab3 session 13", git push.
# 3. Sign out: gh auth logout, or git credential-cache exit and delete the token on GitHub,
#    and capture lab3_s13_logout.png with the token and the sign-out confirmation.
# 4. Open the commit on github.com and confirm the script, its output and your screenshots are there.
#
# ## What goes in the report
#
# 1. Your inventory table, with your own ports. For each port labelled `assumed` rather than
#    `probed`, say what you would have to do to turn the label into evidence.
# 2. Defend the three design decisions in the generated policy: a separate table, an accept policy
#    on the chain, and the loopback-only match. For each, say what would go wrong with the opposite
#    choice.
# 3. Your plane separation result. If you found no break, construct one: name a service you could
#    start that would create it, and say which rule would then be doing the work.
# 4. The policy drops traffic to ports that are open and listening. Explain why dropping at the
#    filter is different from stopping the service, and name one situation where each is the right
#    answer.
