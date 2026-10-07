#!/usr/bin/env python3

# Test topic subscription. All SUBSCRIBE requests are denied. Check this
# produces the correct response, and check the client isn't disconnected (ref:
# issue #1016).

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, PluginConfig
from mosquitto_broker import MosquittoBroker

connect_packet = mqtt_packets.gen_connect("sub-denied-test", username="denied")
connack_packet = mqtt_packets.gen_connack(rc=0)

mid = 53
subscribe_packet = mqtt_packets.gen_subscribe(mid, "qos0/test", 0)
suback_packet = mqtt_packets.gen_suback(mid, 128)

mid_pub = 54
publish_packet = mqtt_packets.gen_publish("topic", qos=1, payload="test", mid=mid_pub)
puback_packet = mqtt_packets.gen_puback(mid_pub)

port = mosq_test.get_port()
broker_config = BrokerConfig(
    listeners = [ ListenerConfig(port=port) ],
    plugins = [
        PluginConfig(
            path=mosq_paths.test_plugin('auth_plugin_acl_sub_denied'),
        )
    ],
    allow_anonymous=False,
)
broker = MosquittoBroker(config=broker_config)
with broker:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

    mosq_test.do_send_receive(sock, publish_packet, puback_packet, "puback")
    sock.close()
