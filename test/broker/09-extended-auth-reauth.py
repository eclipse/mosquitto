#!/usr/bin/env python3

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, PluginConfig
from mosquitto_broker import MosquittoBroker

# First authentication succeeds
props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "repeat")
props += mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_DATA, "repeat")
connect_packet = mqtt_packets.gen_connect("client-params-test", proto_ver=5, properties=props)

props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "repeat")
connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5, properties=props)

# Reauthentication fails
props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "repeat")
props += mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_DATA, "repeat")
auth_packet = mqtt_packets.gen_auth(reason_code=mqtt5_rc.REAUTHENTICATE, properties=props)
disconnect_packet = mqtt_packets.gen_disconnect(reason_code=mqtt5_rc.NOT_AUTHORIZED, proto_ver=5)

port = mosq_test.get_port()
broker_config = BrokerConfig(
    listeners = [ ListenerConfig(port=port) ],
    plugins = [ PluginConfig(path=mosq_paths.test_plugin('auth_plugin_extended_reauth')) ],
)
broker = MosquittoBroker(config=broker_config)
with broker:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)
    mosq_test.do_send_receive(sock, auth_packet, disconnect_packet)
    sock.close()
