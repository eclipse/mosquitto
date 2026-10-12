#!/usr/bin/env python3

# Test whether a persistent client that disconnects with DISCONNECT has its
# will published when it reconnects. It shouldn't. Bug 1273:
# https://github.com/eclipse-mosquitto/mosquitto/issues/1273

from mosq_test_helper import *


def do_test(proto_ver):
    connect1_packet = mqtt_packets.gen_connect("will-reconnect-helper", proto_ver=proto_ver)
    connack1_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    mid = 1
    subscribe1_packet = mqtt_packets.gen_subscribe(mid, "will/reconnect/test", 0, proto_ver=proto_ver)
    suback1_packet = mqtt_packets.gen_suback(mid, 0, proto_ver=proto_ver)

    connect2_packet = mqtt_packets.gen_connect("will-1273", will_topic="will/reconnect/test", will_payload=b"will msg",clean_session=False, proto_ver=proto_ver, session_expiry=60)
    connack2a_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)
    connack2b_packet = mqtt_packets.gen_connack(rc=0, flags=1, proto_ver=proto_ver)

    disconnect_packet = mqtt_packets.gen_disconnect(proto_ver=proto_ver)

    publish_packet = mqtt_packets.gen_publish("will/reconnect/test", qos=0, payload="alive", proto_ver=proto_ver)

    connect2_packet_clear = mqtt_packets.gen_connect("will-1273", proto_ver=proto_ver)

    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)
    with broker:
        # Connect and subscribe will-sub
        sock1 = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=30, port=port, connack_error="connack1")
        mosq_test.do_send_receive(sock1, subscribe1_packet, suback1_packet, "suback")

        # Connect will-1273
        sock2 = mosq_test.do_client_connect(connect2_packet, connack2a_packet, timeout=30, port=port)
        # Publish our "alive" message
        sock2.send(publish_packet)
        # Clean disconnect
        sock2.send(disconnect_packet)

        # will-1273 should get the "alive"
        mosq_test.expect_packet(sock1, "publish1", publish_packet)

        sock2.close()

        # Reconnect
        sock2 = mosq_test.do_client_connect(connect2_packet, connack2b_packet, timeout=30, port=port, connack_error="connack2")
        # will-1273 to publish "alive" again, and will-sub to receive it.
        sock2.send(publish_packet)
        mosq_test.expect_packet(sock1, "publish2", publish_packet)
        # Do a ping to make sure there are no other packets received.
        mosq_test.do_ping(sock1)
        sock1.close()
        sock2.close()

        sock2 = mosq_test.do_client_connect(connect2_packet_clear, connack1_packet, timeout=30, port=port, connack_error="connack clear")
        sock2.close()


if __name__ == '__main__':
    do_test(proto_ver=4)
    do_test(proto_ver=5)
