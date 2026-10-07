#!/usr/bin/env python3

# Test whether maximum packet size is honoured on a PUBLISH to a client
# MQTTv5

from mosq_test_helper import *

def do_test():
    props = mqtt5_props.gen_uint32_prop(mqtt5_props.MAXIMUM_PACKET_SIZE, 40)
    connect_packet = mqtt_packets.gen_connect("12-max-publish-qos1", proto_ver=5, properties=props)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    mid = 1
    subscribe_packet = mqtt_packets.gen_subscribe(mid, "12/max/publish/qos1/test/topic", 1, proto_ver=5)
    suback_packet = mqtt_packets.gen_suback(mid, 1, proto_ver=5)

    mid=1
    publish1_packet = mqtt_packets.gen_publish(topic="12/max/publish/qos1/test/topic", mid=mid, qos=1, payload="1234", proto_ver=5)
    puback1_packet = mqtt_packets.gen_puback(mid, proto_ver=5)

    mid=2
    props = mqtt5_props.gen_byte_prop(mqtt5_props.PAYLOAD_FORMAT_INDICATOR, 1)
    publish2_packet = mqtt_packets.gen_publish(topic="12/max/publish/qos1/test/topic", mid=mid, qos=1, payload="56", proto_ver=5, properties=props)
    puback2_packet = mqtt_packets.gen_puback(mid, proto_ver=5)

    mid=3
    publish3_packet = mqtt_packets.gen_publish(topic="12/max/publish/qos1/test/topic", mid=mid, qos=1, payload="789", proto_ver=5)
    puback3_packet = mqtt_packets.gen_puback(mid, proto_ver=5)

    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)
    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet)

        mosq_test.do_send_receive(sock, publish1_packet, puback1_packet, "puback 1")
        # We shouldn't receive the publish here because it is > MAXIMUM_PACKET_SIZE
        mosq_test.do_ping(sock)

        mosq_test.do_send_receive(sock, publish2_packet, puback2_packet, "puback 2")
        # We shouldn't receive the publish here because it is > MAXIMUM_PACKET_SIZE
        mosq_test.do_ping(sock)

        sock.send(publish3_packet)
        mosq_test.receive_unordered(sock, puback3_packet, publish3_packet, "puback 3/publish3")


if __name__ == '__main__':
    do_test()
