import socket, time

socks = []
for port in (8081, 8082, 8085):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', port))
    s.listen(8)
    socks.append(s)
    print('listening on 127.0.0.1:%d' % port)

print('leave this running; press Ctrl-C when the lab says so')
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    for s in socks:
        s.close()
