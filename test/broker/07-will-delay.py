#!/usr/bin/env python3
# Test whether a client will is transmitted with a delay correctly.
# MQTT 5

from mosq_test_helper import *

def do_test(clean_session):
    mid = 1
    connect1_packet = mqtt_packets.gen_connect("will-delay-test", proto_ver=5)
    connack1_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    props = mqtt5_props.gen_uint32_prop(mqtt5_props.SESSION_EXPIRY_INTERVAL, 60)
    will_props = mqtt5_props.gen_uint32_prop(mqtt5_props.WILL_DELAY_INTERVAL, 3)
    connect2_packet = mqtt_packets.gen_connect("will-delay-helper", proto_ver=5, properties=props, will_topic="will/delay/test", will_payload=b"will delay", will_qos=2, will_properties=will_props, clean_session=clean_session)
    connack2_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    subscribe_packet = mqtt_packets.gen_subscribe(mid, "will/delay/test", 0, proto_ver=5)
    suback_packet = mqtt_packets.gen_suback(mid, 0, proto_ver=5)

    publish_packet = mqtt_packets.gen_publish("will/delay/test", qos=0, payload="will delay", proto_ver=5)

    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)

    with broker:
        sock1 = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=30, port=port)
        mosq_test.do_send_receive(sock1, subscribe_packet, suback_packet, "suback")

        sock2 = mosq_test.do_client_connect(connect2_packet, connack2_packet, timeout=30, port=port)
        sock2.close()

        t_start = time.time()
        mosq_test.expect_packet(sock1, "publish", publish_packet)
        t_finish = time.time()
        sock1.close()
        if t_finish - t_start > 2 and t_finish - t_start < 5:
            rc = 0
        else:
            raise ValueError(f"{t_finish - t_start}")


if __name__ == '__main__':
    do_test(clean_session=True)
    do_test(clean_session=False)
