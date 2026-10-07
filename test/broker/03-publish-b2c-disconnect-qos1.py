#!/usr/bin/env python3

# Does an interrupted QoS 1 flow from broker to client get handled correctly?

from mosq_test_helper import *

def helper(port):
    connect_packet = mqtt_packets.gen_connect("03-b2c-disco-qos1-helper")
    connack_packet = mqtt_packets.gen_connack(rc=0)

    mid = 128
    publish_packet = mqtt_packets.gen_publish("03/b2c/qos1/disconnect/test", qos=1, mid=mid, payload="disconnect-message")
    puback_packet = mqtt_packets.gen_puback(mid)
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, connack_error="helper connack", port=port)
    mosq_test.do_send_receive(sock, publish_packet, puback_packet, "helper puback")
    sock.close()


def do_test(proto_ver):
    port = mosq_test.get_port()

    rc = 1
    mid = 3265
    connect_packet = mqtt_packets.gen_connect("03-b2c-disco-qos1", clean_session=False, proto_ver=proto_ver, session_expiry=60)
    connack1_packet = mqtt_packets.gen_connack(flags=0, rc=0, proto_ver=proto_ver)
    connack2_packet = mqtt_packets.gen_connack(flags=1, rc=0, proto_ver=proto_ver)
    connect_packet_clear = mqtt_packets.gen_connect("03-b2c-disco-qos1", proto_ver=proto_ver)

    subscribe_packet = mqtt_packets.gen_subscribe(mid, "03/b2c/qos1/disconnect/test", 1, proto_ver=proto_ver)
    suback_packet = mqtt_packets.gen_suback(mid, 1, proto_ver=proto_ver)

    mid = 1
    publish_packet = mqtt_packets.gen_publish("03/b2c/qos1/disconnect/test", qos=1, mid=mid, payload="disconnect-message", proto_ver=proto_ver)
    publish_dup_packet = mqtt_packets.gen_publish("03/b2c/qos1/disconnect/test", qos=1, mid=mid, payload="disconnect-message", dup=True, proto_ver=proto_ver)
    puback_packet = mqtt_packets.gen_puback(mid, proto_ver=proto_ver)

    mid = 3266
    publish2_packet = mqtt_packets.gen_publish("03/b2c/qos1/outgoing", qos=1, mid=mid, payload="outgoing-message", proto_ver=proto_ver)
    puback2_packet = mqtt_packets.gen_puback(mid, proto_ver=proto_ver)

    broker = MosquittoBroker(port=port)
    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack1_packet, port=port)

        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        helper(port)
        # Should have now received a publish command

        mosq_test.expect_packet(sock, "publish", publish_packet)
        # Send our outgoing message. When we disconnect the broker
        # should get rid of it and assume we're going to retry.
        sock.send(publish2_packet)
        sock.close()

        sock = mosq_test.do_client_connect(connect_packet, connack2_packet, port=port)
        mosq_test.expect_packet(sock, "dup publish", publish_dup_packet)
        sock.send(puback_packet)
        sock.close()

        # clear session
        sock = mosq_test.do_client_connect(connect_packet_clear, connack1_packet, port=port)
        sock.close()


if __name__ == '__main__':
    do_test(proto_ver=4)
    do_test(proto_ver=5)
