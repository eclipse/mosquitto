#!/usr/bin/env python3

# Test whether a PUBLISH with a retain set when retains are disabled results in
# the correct DISCONNECT.

from mosq_test_helper import *
from broker_config import BrokerConfig

def do_test(proto_ver):
    mid = 1
    connect_packet = mqtt_packets.gen_connect("pub-qos1-test", proto_ver=5)

    props = mqtt5_props.gen_byte_prop(mqtt5_props.RETAIN_AVAILABLE, 0)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5, properties=props)

    publish_packet = mqtt_packets.gen_publish("pub/qos1/test", qos=1, mid=mid, payload="message", retain=True, proto_ver=5)
    puback_packet = mqtt_packets.gen_puback(mid, proto_ver=5)

    disconnect_packet = mqtt_packets.gen_disconnect(reason_code=154, proto_ver=5)

    port = mosq_test.get_port()
    broker_config = BrokerConfig(retain_available=False)
    broker = MosquittoBroker(port=port, config=broker_config)
    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        mosq_test.do_send_receive(sock, publish_packet, disconnect_packet, "disconnect")
        sock.close()


do_test(proto_ver=4)
do_test(proto_ver=5)
