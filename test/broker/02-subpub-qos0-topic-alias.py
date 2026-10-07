#!/usr/bin/env python3

# Test whether "topic alias" works to the broker
# MQTT v5

from mosq_test_helper import *

def do_test():
    connect1_packet = mqtt_packets.gen_connect("02-subpub-qos0-topic-alias", proto_ver=5)
    connack1_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    connect2_packet = mqtt_packets.gen_connect("02-subpub-qos0-topic-alias-helper", proto_ver=5)
    connack2_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    mid = 1
    subscribe_packet = mqtt_packets.gen_subscribe(mid, "02/subpub/topic-alias/alias", 0, proto_ver=5)
    suback_packet = mqtt_packets.gen_suback(mid, 0, proto_ver=5)

    props = mqtt5_props.gen_uint16_prop(mqtt5_props.TOPIC_ALIAS, 3)
    publish1_packet = mqtt_packets.gen_publish("02/subpub/topic-alias/alias", qos=0, payload="message", proto_ver=5, properties=props)

    props = mqtt5_props.gen_uint16_prop(mqtt5_props.TOPIC_ALIAS, 3)
    publish2s_packet = mqtt_packets.gen_publish("", qos=0, payload="message", proto_ver=5, properties=props)
    publish2r_packet = mqtt_packets.gen_publish("02/subpub/topic-alias/alias", qos=0, payload="message", proto_ver=5)


    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)

    with broker:
        sock1 = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=5, port=port)
        sock2 = mosq_test.do_client_connect(connect2_packet, connack2_packet, timeout=5, port=port)

        sock1.send(publish1_packet)

        mosq_test.do_send_receive(sock2, subscribe_packet, suback_packet, "suback")

        sock1.send(publish2s_packet)

        mosq_test.expect_packet(sock2, "publish2r", publish2r_packet)

        sock1.close()
        sock2.close()



if __name__ == '__main__':
    do_test()
