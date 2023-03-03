#!/usr/bin/env python3

# Test whether a client produces a correct connect and subsequent disconnect when using SSL.

# The client should connect to port 1888 with keepalive=60, clean session set,
# and client id 08-ssl-connect-no-auth
# It should use the CA certificate ssl/test-ca.crt for verifying the server.
# The test will send a CONNACK message to the client with rc=0. Upon receiving
# the CONNACK and verifying that rc=0, the client should send a DISCONNECT
# message. If rc!=0, the client should exit with an error.

from mosq_test_helper import *

if sys.version < '2.7':
    print("WARNING: SSL not supported on Python 2.6")
    exit(0)

def do_test(client_cmd):
    port = mosq_test.get_port()

    rc = 1
    connect_packet = mosq_test.gen_connect("08-ssl-connect-no-auth")
    connack_packet = mosq_test.gen_connack(rc=0)
    disconnect_packet = mosq_test.gen_disconnect()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=f"{ssl_dir}/all-ca.crt")
    context.load_cert_chain(certfile=f"{ssl_dir}/server.crt", keyfile=f"{ssl_dir}/server.key")
    ssock = context.wrap_socket(sock, server_side=True)
    ssock.settimeout(10)
    ssock.bind(('', port))
    ssock.listen(5)

    client_args = [mosq_test.get_build_root() + "/test/lib/" + client_cmd, str(port)]
    client = mosq_test.start_client(filename=client_cmd.replace('/', '-'), cmd=client_args)

    try:
        (conn, address) = ssock.accept()
        conn.settimeout(100)

        mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")

        mosq_test.expect_packet(conn, "disconnect", disconnect_packet)
        rc = 0

        conn.close()
    except mosq_test.TestError:
        pass
    finally:
        if mosq_test.wait_for_subprocess(client):
            print("test client not finished")
            rc=1
        ssock.close()
        if rc:
            exit(rc)

do_test("c/08-ssl-connect-no-auth.test")
do_test("cpp/08-ssl-connect-no-auth.test")
