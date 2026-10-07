#!/usr/bin/env python3

# Test whether message parameters are passed to the plugin acl check function.

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, PluginConfig
from mosquitto_broker import MosquittoBroker

def do_test(proto_ver):
    connect_packet = mqtt_packets.gen_connect("delayed-auth-test", username="delayed-username", password="good", proto_ver=proto_ver)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    connect_packet2 = mqtt_packets.gen_connect("delayed-auth-test", username="delayed-username", password="bad", proto_ver=proto_ver)
    if proto_ver == 5:
        connack_packet2 = mqtt_packets.gen_connack(rc=mqtt5_rc.NOT_AUTHORIZED, proto_ver=proto_ver, property_helper=False)
    else:
        connack_packet2 = mqtt_packets.gen_connack(rc=5, proto_ver=proto_ver)

    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port) ],
        plugins = [ PluginConfig(path=mosq_paths.test_plugin('auth_plugin_delayed')) ],
        allow_anonymous=False,
    )
    broker = MosquittoBroker(config=broker_config)
    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)
        sock.close()
        sock = mosq_test.do_client_connect(connect_packet2, connack_packet2, timeout=20, port=port)
        sock.close()

        # Connect, disconnect, reconnect - try to trigger #3388
        for i in range(0, 50):
            try:
                sock = mosq_test.client_connect_only(port=port)
                break
            except ConnectionRefusedError:
                time.sleep(0.1)
        sock.send(connect_packet)
        sock.close()
        # Give the tick time to trigger
        time.sleep(0.5)
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)
        sock.close()


do_test(4)
do_test(5)
