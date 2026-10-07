#!/usr/bin/env python3

# Test whether a client with a will delay recovers on the client reconnecting
# MQTT 5

from mosq_test_helper import *


def do_test(clean_session):
    mid = 1
    connect1_packet = mqtt_packets.gen_connect("will-delay-recovery", proto_ver=5)
    connack1_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    connect_props = mqtt5_props.gen_uint32_prop(mqtt5_props.SESSION_EXPIRY_INTERVAL, 30)
    props = mqtt5_props.gen_uint32_prop(mqtt5_props.WILL_DELAY_INTERVAL, 3)
    connect2_packet = mqtt_packets.gen_connect("will-delay-recovery-helper", proto_ver=5, will_topic="will/delay/recovery/test", will_payload=b"will delay", will_properties=props, clean_session=clean_session, properties=connect_props)
    connack2a_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)
    if clean_session == True:
        connack2b_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)
    else:
        connack2b_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5, flags=1)

    subscribe_packet = mqtt_packets.gen_subscribe(mid, "will/delay/recovery/test", 0, proto_ver=5)
    suback_packet = mqtt_packets.gen_suback(mid, 0, proto_ver=5)

    connect2_packet_clear = mqtt_packets.gen_connect("will-delay-recovery-helper", proto_ver=5)

    will_packet = mqtt_packets.gen_publish(topic="will/delay/recovery/test", payload="will delay", qos=0, proto_ver=5)

    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)
    with broker:
        sock1 = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=30, port=port)
        mosq_test.do_send_receive(sock1, subscribe_packet, suback_packet, "suback")

        sock2 = mosq_test.do_client_connect(connect2_packet, connack2a_packet, timeout=30, port=port)
        sock2.close()

        time.sleep(1)
        sock2 = mosq_test.do_client_connect(connect2_packet, connack2b_packet, timeout=30, port=port)
        time.sleep(3)

        # The client2 has reconnected within the will delay interval, which has now
        # passed.
        if clean_session:
            # The old session has ended, so we should receive the will
            mosq_test.expect_packet(sock1, "will", will_packet)
        else:
            # We should not have received the will at this point.
            mosq_test.do_ping(sock1)

        sock1.close()
        sock2.close()

        sock2 = mosq_test.do_client_connect(connect2_packet_clear, connack1_packet, timeout=30, port=port)
        sock2.close()


if __name__ == '__main__':
    do_test(clean_session=True)
    do_test(clean_session=False)
