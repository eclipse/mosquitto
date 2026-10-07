#!/usr/bin/env python3

# Test whether a client with a will delay handles correctly on the client reconnecting
# First connection is durable, second is clean session, and without a will, so the will should not be received.
# MQTT 5

from mosq_test_helper import *


def do_test():
    mid = 1
    connect1_packet = mqtt_packets.gen_connect("will-delay-reconnect-test", proto_ver=5)
    connack1_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    props = mqtt5_props.gen_uint32_prop(mqtt5_props.SESSION_EXPIRY_INTERVAL, 60)
    will_props = mqtt5_props.gen_uint32_prop(mqtt5_props.WILL_DELAY_INTERVAL, 3)
    connect2a_packet = mqtt_packets.gen_connect("will-delay-reconnect-helper", proto_ver=5, will_topic="will/delay/reconnect/test", will_payload=b"will delay", will_properties=will_props, clean_session=False, properties=props)
    connack2a_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    connect2b_packet = mqtt_packets.gen_connect("will-delay-reconnect-helper", proto_ver=5, clean_session=False)
    connack2b_packet = mqtt_packets.gen_connack(rc=0, flags=1, proto_ver=5)

    subscribe_packet = mqtt_packets.gen_subscribe(mid, "will/delay/reconnect/test", 0, proto_ver=5)
    suback_packet = mqtt_packets.gen_suback(mid, 0, proto_ver=5)

    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)
    with broker:
        sock1 = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=30, port=port)
        mosq_test.do_send_receive(sock1, subscribe_packet, suback_packet, "suback")

        sock2 = mosq_test.do_client_connect(connect2a_packet, connack2a_packet, timeout=30, port=port)
        sock2.close()

        time.sleep(1)
        sock2 = mosq_test.do_client_connect(connect2b_packet, connack2b_packet, timeout=30, port=port)
        time.sleep(3)

        # The client2 has reconnected within the original will delay interval, which has now
        # passed, but it should have been deleted anyway. Disconnect and see
        # whether we get the old will. We should not.
        sock2.close()

        mosq_test.do_ping(sock1)
        sock1.close()


if __name__ == '__main__':
    do_test()
