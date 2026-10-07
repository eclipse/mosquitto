#!/usr/bin/env python3

# client 1 subscribes to normal-topic
# client 2 susbscribes to response-topic
# client 2 publishes message to normal-topic with response-topic property and correlation-data property
# client 1 receives message, publishes a response on response-topic
# client 2 receives message, checks payload

from mosq_test_helper import *

def do_test():
    connect_packet1 = mqtt_packets.gen_connect("client1", proto_ver=5)
    connect_packet2 = mqtt_packets.gen_connect("client2", proto_ver=5)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    subscribe_packet1 = mqtt_packets.gen_subscribe(mid=1, topic="normal/topic", qos=0, proto_ver=5)
    subscribe_packet2 = mqtt_packets.gen_subscribe(mid=1, topic="response/topic", qos=0, proto_ver=5)
    suback_packet = mqtt_packets.gen_suback(mid=1, qos=0, proto_ver=5)

    props = mqtt5_props.gen_string_prop(mqtt5_props.RESPONSE_TOPIC, "response/topic")
    props = mqtt5_props.gen_string_prop(mqtt5_props.CORRELATION_DATA, "45vyvynq30q3vt4 nuy893b4v3")
    publish_packet2 = mqtt_packets.gen_publish(topic="normal/topic", qos=0, payload="2", proto_ver=5, properties=props)

    publish_packet1 = mqtt_packets.gen_publish(topic="response/topic", qos=0, payload="22", proto_ver=5)

    disconnect_client_packet = mqtt_packets.gen_disconnect(proto_ver=5, properties=props)

    disconnect_server_packet = mqtt_packets.gen_disconnect(proto_ver=5, reason_code=130)

    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)
    with broker:
        sock1 = mosq_test.do_client_connect(connect_packet1, connack_packet, port=port)
        sock2 = mosq_test.do_client_connect(connect_packet2, connack_packet, port=port)

        mosq_test.do_send_receive(sock1, subscribe_packet1, suback_packet, "subscribe1")
        mosq_test.do_send_receive(sock2, subscribe_packet2, suback_packet, "subscribe2")

        sock2.send(publish_packet2)
        mosq_test.expect_packet(sock1, "publish1", publish_packet2)
        # FIXME - it would be better to extract the property and payload, even though we know them
        sock1.send(publish_packet1)
        mosq_test.expect_packet(sock2, "publish2", publish_packet1)
        sock1.close()
        sock2.close()


if __name__ == '__main__':
    do_test()
