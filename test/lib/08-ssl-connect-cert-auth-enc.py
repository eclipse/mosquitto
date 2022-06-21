#!/usr/bin/env python3

# Test whether a client produces a correct connect and subsequent disconnect when using SSL.
# Client must provide a certificate.

# The client should connect to port 1888 with keepalive=60, clean session set,
# and client id 08-ssl-connect-crt-auth
# It should use the CA certificate ssl/test-root-ca.crt for verifying the server.
# The test will send a CONNACK message to the client with rc=0. Upon receiving
# the CONNACK and verifying that rc=0, the client should send a DISCONNECT
# message. If rc!=0, the client should exit with an error.

from mosq_test_helper import *

port = mosq_test.get_lib_port()

if sys.version < '2.7':
    print("WARNING: SSL not supported on Python 2.6")
    exit(0)

rc = 1
keepalive = 60
connect_packet = mosq_test.gen_connect("08-ssl-connect-crt-auth-enc", keepalive=keepalive)
connack_packet = mosq_test.gen_connack(rc=0)
disconnect_packet = mosq_test.gen_disconnect()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ssock = ssl.wrap_socket(sock, ca_certs=f"{ssl_dir}/all-ca.crt",
        keyfile=f"{ssl_dir}/server.key", certfile=f"{ssl_dir}/server.crt",
        server_side=True, cert_reqs=ssl.CERT_REQUIRED)
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
    conn.settimeout(10)

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")
    mosq_test.expect_packet(conn, "disconnect", disconnect_packet)
    rc = 0

    conn.close()
except mosq_test.TestError:
    pass
finally:
    client.wait()
    ssock.close()
    if rc:
        (stdo, stde) = client.communicate()
        print(stde.decode('utf-8'))

exit(rc)
