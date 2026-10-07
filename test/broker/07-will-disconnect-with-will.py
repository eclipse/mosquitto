#!/usr/bin/env python3

# Test whether a client will is transmitted when a client disconnects with DISCONNECT with will.
# MQTT 5

from mosq_test_helper import *

def do_test():
    mid = 1
    connect1_packet = mqtt_packets.gen_connect("will-with-disconnect-test", proto_ver=5)
    connack1_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    connect2_packet = mqtt_packets.gen_connect("will-with-disconnect-helper", proto_ver=5, will_topic="will/with/disconnect/test", will_payload=b"will delay", will_qos=2)
    connack2_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)
    disconnect_packet = mqtt_packets.gen_disconnect(reason_code=4, proto_ver=5)

    subscribe_packet = mqtt_packets.gen_subscribe(mid, "will/with/disconnect/test", 0, proto_ver=5)
    suback_packet = mqtt_packets.gen_suback(mid, 0, proto_ver=5)

    publish_packet = mqtt_packets.gen_publish("will/with/disconnect/test", qos=0, payload="will delay", proto_ver=5)

    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)
    with broker:
        sock1 = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=30, port=port)
        mosq_test.do_send_receive(sock1, subscribe_packet, suback_packet, "suback")

        sock2 = mosq_test.do_client_connect(connect2_packet, connack2_packet, timeout=30, port=port)
        sock2.send(disconnect_packet)

        mosq_test.expect_packet(sock1, "publish", publish_packet)
        sock2.close()
        sock1.close()


if __name__ == '__main__':
    do_test()
