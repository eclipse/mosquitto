#!/usr/bin/env python3

from mosq_test_helper import *

port = mosq_test.get_lib_port()

if sys.version < '2.7':
    print("WARNING: SSL not supported on Python 2.6")
    exit(0)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=f"{ssl_dir}/all-ca.crt")
context.load_cert_chain(certfile=f"{ssl_dir}/server.crt", keyfile=f"{ssl_dir}/server.key")
context.verify_mode = ssl.CERT_REQUIRED
ssock = context.wrap_socket(sock, server_side=True)
ssock.settimeout(10)
ssock.bind(('', port))
ssock.listen(5)

client_args = sys.argv[1:]
env = dict(os.environ)
env['LD_LIBRARY_PATH'] = mosq_test.get_build_root() + '/lib:' + mosq_test.get_build_root() + '/lib/cpp'
try:
    pp = env['PYTHONPATH']
except KeyError:
    pp = ''
env['PYTHONPATH'] = mosq_test.get_build_root() + '/lib/python:'+pp
client = mosq_test.start_client(filename=sys.argv[1].replace('/', '-'), cmd=client_args, env=env, port=port)

try:
    (conn, address) = ssock.accept()

    conn.close()
except ssl.SSLError:
    # Expected error due to ca certs not matching.
    pass
except mosq_test.TestError:
    pass
finally:
    time.sleep(1.0)
    if mosq_test.wait_for_subprocess(client):
        print("test client not finished")
        rc=1
    ssock.close()

if client.returncode == 0:
    exit(0)
else:
    exit(1)

