#!/usr/bin/env python3

# Check whether an incoming bridge connection receives its own messages. It
# shouldn't because for v3.1 and v3.1.1 we have no-local set for all bridges.

from mosq_test_helper import *

mosq_test.require_features(["INC_BRIDGE_SUPPORT"])

def do_test(proto_ver_connect, proto_ver_msgs, sub_opts):
    connect_packet = mqtt_packets.gen_connect("bridge-test", proto_ver=proto_ver_connect)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver_msgs)

    mid = 1
    subscribe_packet = mqtt_packets.gen_subscribe(mid, "loop/test", 0 | sub_opts, proto_ver=proto_ver_msgs)
    suback_packet = mqtt_packets.gen_suback(mid, 0, proto_ver=proto_ver_msgs)

    publish_packet = mqtt_packets.gen_publish("loop/test", qos=0, payload="message", proto_ver=proto_ver_msgs)

    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)
    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")
        sock.send(publish_packet)
        mosq_test.do_ping(sock)
        sock.close()


if __name__ == '__main__':
    do_test(128+3, 3, 0)
    do_test(128+4, 4, 0)
    do_test(5, 5, mqtt5_opts.MQTT_SUB_OPT_NO_LOCAL)
