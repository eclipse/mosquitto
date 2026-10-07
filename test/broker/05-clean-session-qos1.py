#!/usr/bin/env python3

# Test whether a clean session client has a QoS 1 message queued for it.

from mosq_test_helper import *

def helper(port):
    connect_packet = mqtt_packets.gen_connect("05-clean-qos1-test-helper")
    connack_packet = mqtt_packets.gen_connack(rc=0)

    mid = 128
    publish_packet = mqtt_packets.gen_publish("qos1/05-clean_session/test", qos=1, mid=mid, payload="clean-session-message")
    puback_packet = mqtt_packets.gen_puback(mid)

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
    mosq_test.do_send_receive(sock, publish_packet, puback_packet, "puback")

    sock.close()


def do_test(proto_ver):
    mid = 109
    connect_packet = mqtt_packets.gen_connect("05-clean-session", clean_session=False, proto_ver=proto_ver, session_expiry=60)
    connack1_packet = mqtt_packets.gen_connack(flags=0, rc=0, proto_ver=proto_ver)
    connack2_packet = mqtt_packets.gen_connack(flags=1, rc=0, proto_ver=proto_ver)

    disconnect_packet = mqtt_packets.gen_disconnect(proto_ver=proto_ver)

    subscribe_packet = mqtt_packets.gen_subscribe(mid, "qos1/05-clean_session/test", 1, proto_ver=proto_ver)
    suback_packet = mqtt_packets.gen_suback(mid, 1, proto_ver=proto_ver)

    mid = 1
    publish_packet = mqtt_packets.gen_publish("qos1/05-clean_session/test", qos=1, mid=mid, payload="clean-session-message", proto_ver=proto_ver)
    puback_packet = mqtt_packets.gen_puback(mid, proto_ver=proto_ver)

    connect_packet_clear = mqtt_packets.gen_connect("05-clean-session", clean_session=True, proto_ver=proto_ver, session_expiry=0)

    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)
    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack1_packet, port=port, connack_error="connack 1")
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        sock.send(disconnect_packet)
        sock.close()

        helper(port)

        # Now reconnect and expect a publish message.
        sock = mosq_test.do_client_connect(connect_packet, connack2_packet, timeout=30, port=port, connack_error="connack 2")
        mosq_test.expect_packet(sock, "publish", publish_packet)
        sock.send(puback_packet)
        sock.close()

        # Clear the session
        sock = mosq_test.do_client_connect(connect_packet_clear, connack1_packet, port=port, connack_error="connack clear")
        sock.close()


if __name__ == '__main__':
    do_test(proto_ver=4)
    do_test(proto_ver=5)
