import hashlib, pathlib, shutil

digest = lambda p: hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
cfg = pathlib.Path('service.conf')
cfg.write_text('tls_min_version = 1.2\nverify_peer = true\ntimeout = 30\n')

shutil.copy2(cfg, 'service.conf.bak')
before = digest(cfg)
print('checkpoint:', before)

cfg.write_text(cfg.read_text().replace('verify_peer = true', 'verify_peer = false'))
print('changed  :', digest(cfg))

ok = ' verify_peer = true' in cfg.read_text()
print('success criterion met:' , ok, '-> rollback triggered:', not ok)

if not ok:
    shutil.copy2('service.conf.bak', cfg)
    print('restored :', digest(cfg), '| faithful:', digest(cfg)  == before)

