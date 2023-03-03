#!/usr/bin/env python3

# Test whether a client sends a correct PUBLISH to a topic with QoS 2 and responds to a disconnect.

from mosq_test_helper import *

def do_test(client_cmd):
    port = mosq_test.get_port()

    rc = 1
    connect_packet = mosq_test.gen_connect("publish-qos2-test")
    connack_packet = mosq_test.gen_connack(rc=0)

    disconnect_packet = mosq_test.gen_disconnect()

    mid = 1
    publish_packet = mosq_test.gen_publish("pub/qos2/test", qos=2, mid=mid, payload="message")
    publish_dup_packet = mosq_test.gen_publish("pub/qos2/test", qos=2, mid=mid, payload="message", dup=True)
    pubrec_packet = mosq_test.gen_pubrec(mid)
    pubrel_packet = mosq_test.gen_pubrel(mid)
    pubcomp_packet = mosq_test.gen_pubcomp(mid)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(10)
    sock.bind(('', port))
    sock.listen(5)

    client_args = [client_cmd, str(port)]
    env = dict(os.environ)
    env['LD_LIBRARY_PATH'] = mosq_test.get_build_root() + '/lib:' + mosq_test.get_build_root() + '/lib/cpp'

    client = mosq_test.start_client(filename=client_cmd.replace('/', '-'), cmd=client_args, env=env)

    try:
        (conn, address) = sock.accept()
        conn.settimeout(10)

        mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")

        mosq_test.expect_packet(conn, "publish", publish_packet)
        # Disconnect client. It should reconnect.
        conn.close()

        (conn, address) = sock.accept()
        conn.settimeout(15)

        mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")
        mosq_test.do_receive_send(conn, publish_dup_packet, pubrec_packet, "retried publish")

        mosq_test.expect_packet(conn, "pubrel", pubrel_packet)
        # Disconnect client. It should reconnect.
        conn.close()

        (conn, address) = sock.accept()
        conn.settimeout(15)

        # Complete connection and message flow.
        mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")
        mosq_test.do_receive_send(conn, pubrel_packet, pubcomp_packet, "retried pubrel")

        mosq_test.expect_packet(conn, "disconnect", disconnect_packet)
        rc = 0

        conn.close()
    except mosq_test.TestError:
        pass
    finally:
        sock.close()
        if mosq_test.wait_for_subprocess(client):
            print("test client not finished")
            rc=1
            exit(1)

do_test("c/03-publish-c2b-qos2-disconnect.test")
do_test("cpp/03-publish-c2b-qos2-disconnect.test")
