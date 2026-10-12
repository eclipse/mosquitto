#!/usr/bin/env python3

# Test whether a client that connects with a will delay that is shorter than
# their session expiry interval has their will published.
# MQTT 5
# https://github.com/eclipse-mosquitto/mosquitto/issues/1401

from mosq_test_helper import *

def do_test():
    mid = 1
    connect1_packet = mqtt_packets.gen_connect("will-session-exp2", proto_ver=5)
    connack1_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    will_props = mqtt5_props.gen_uint32_prop(mqtt5_props.WILL_DELAY_INTERVAL, 2)
    connect_props = mqtt5_props.gen_uint32_prop(mqtt5_props.SESSION_EXPIRY_INTERVAL, 4)

    connect2_packet = mqtt_packets.gen_connect("will-session-exp2-helper", proto_ver=5, properties=connect_props, will_topic="will/session/expiry2/test", will_payload=b"will delay", will_qos=2, will_properties=will_props)
    connack2_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    subscribe_packet = mqtt_packets.gen_subscribe(mid, "will/session/expiry2/test", 0, proto_ver=5)
    suback_packet = mqtt_packets.gen_suback(mid, 0, proto_ver=5)

    publish_packet = mqtt_packets.gen_publish("will/session/expiry2/test", qos=0, payload="will delay", proto_ver=5)

    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)
    with broker:
        sock1 = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=30, port=port, connack_error="connack1")
        mosq_test.do_send_receive(sock1, subscribe_packet, suback_packet, "suback")

        sock2 = mosq_test.do_client_connect(connect2_packet, connack2_packet, timeout=30, port=port, connack_error="connack2")
        time.sleep(1)
        sock2.close()

        # Wait for session to expire
        time.sleep(3)
        mosq_test.expect_packet(sock1, "publish", publish_packet)
        sock1.close()


if __name__ == '__main__':
    do_test()
