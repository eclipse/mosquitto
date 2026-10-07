#!/usr/bin/env python3

# Test whether a client sends a correct PUBLISH to a topic with QoS 1, then responds correctly to a disconnect.

from mosq_test_helper import *

def do_test(client_cmd):
    port = mosq_test.get_port()

    rc = 1
    connect_packet = mqtt_packets.gen_connect("publish-qos1-test")
    connack_packet = mqtt_packets.gen_connack(rc=0)

    disconnect_packet = mqtt_packets.gen_disconnect()

    mid = 1
    publish_packet = mqtt_packets.gen_publish("pub/qos1/test", qos=1, mid=mid, payload="message")
    publish_packet_dup = mqtt_packets.gen_publish("pub/qos1/test", qos=1, mid=mid, payload="message", dup=True)
    puback_packet = mqtt_packets.gen_puback(mid)

    sock = mosq_test.listen_sock(port)

    client_args = [client_cmd, str(port)]
    env = mosq_test.env_add_ld_library_path()

    client = mosq_test.start_client(filename=str(client_args).replace('/', '-'), cmd=client_args, env=env)

    try:
        (conn, address) = sock.accept()
        conn.settimeout(15)

        mosq_test.expect_packet(conn, "connect", connect_packet)
        conn.send(connack_packet)

        mosq_test.expect_packet(conn, "publish", publish_packet)
        # Disconnect client. It should reconnect.
        conn.close()

        (conn, address) = sock.accept()
        conn.settimeout(15)

        mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")
        mosq_test.do_receive_send(conn, publish_packet_dup, puback_packet, "retried publish")
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

do_test(Path("c", mosq_test.get_build_type(), "03-publish-c2b-qos1-disconnect.exe"))
if mosq_test.check_features(["WITH_LIB_CPP"]):
    do_test(Path("cpp", mosq_test.get_build_type(), "03-publish-c2b-qos1-disconnect.exe"))
