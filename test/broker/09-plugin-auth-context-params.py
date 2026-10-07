#!/usr/bin/env python3

# Test whether message parameters are passed to the plugin acl check function.

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, PluginConfig
from mosquitto_broker import MosquittoBroker

connect_packet = mqtt_packets.gen_connect("client-params-test", keepalive=42, username="client-username")
connack_packet = mqtt_packets.gen_connack(rc=0)

mid = 2
subscribe_packet = mqtt_packets.gen_subscribe(mid, "param/topic", 1)
suback_packet = mqtt_packets.gen_suback(mid, 1)

mid = 3
publish_packet = mqtt_packets.gen_publish(topic="param/topic", qos=1, payload="payload contents", retain=1, mid=mid)
puback_packet = mqtt_packets.gen_puback(mid)

mid = 1
publish_packet_recv = mqtt_packets.gen_publish(topic="param/topic", qos=1, payload="payload contents", retain=0, mid=mid)


port = mosq_test.get_port()
broker_config = BrokerConfig(
    listeners = [ ListenerConfig(port=port) ],
    plugins = [ PluginConfig(path=mosq_paths.test_plugin(f'auth_plugin_context_params')) ],
    allow_anonymous=False,
)
broker = MosquittoBroker(config=broker_config)
with broker:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)
    sock.close()
