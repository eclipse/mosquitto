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

mosq_test.require_features(["WITH_TLS"])

if sys.version < '2.7':
    print("WARNING: SSL not supported on Python 2.6")
    exit(0)

def do_test(client_cmd):
    rc = 1
    connect_packet = mqtt_packets.gen_connect("08-ssl-connect-crt-auth-enc")
    connack_packet = mqtt_packets.gen_connack(rc=0)
    disconnect_packet = mqtt_packets.gen_disconnect()

    port = mosq_test.get_port()

    ssock = mosq_test.listen_sock(port, f"{ssl_dir}/all-ca.crt", f"{ssl_dir}/server.crt", f"{ssl_dir}/server.key", True)

    client_args = [Path(mosq_test.get_build_root(), "test", "lib") / client_cmd, str(port)]
    client = mosq_test.start_client(filename=str(client_cmd).replace('/', '-'), cmd=client_args)

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
        if mosq_test.wait_for_subprocess(client):
            print("test client not finished")
            rc=1
        ssock.close()
        if rc:
            (stdo, stde) = client.communicate()
            print(stde.decode('utf-8'))
            exit(rc)


do_test(Path("c", mosq_test.get_build_type(), '08-ssl-connect-cert-auth-enc.exe'))
if mosq_test.check_features(["WITH_LIB_CPP"]):
    do_test(Path("cpp", mosq_test.get_build_type(), '08-ssl-connect-cert-auth-enc.exe'))
