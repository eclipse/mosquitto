#!/usr/bin/env python3

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, PluginConfig
from mosquitto_broker import MosquittoBroker

props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "mirror")
props += mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_DATA, "step1")
connect_packet = mqtt_packets.gen_connect("client-params-test", proto_ver=5, properties=props)

# Server to client
props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "mirror")
props += mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_DATA, "1pets")
auth1_packet = mqtt_packets.gen_auth(reason_code=mqtt5_rc.CONTINUE_AUTHENTICATION, properties=props)

# Client to server
props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "mirror")
props += mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_DATA, "supercalifragilisticexpialidocious")
auth2_packet = mqtt_packets.gen_auth(reason_code=mqtt5_rc.CONTINUE_AUTHENTICATION, properties=props)

props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "mirror")
connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5, properties=props)


port = mosq_test.get_port()
broker_config = BrokerConfig(
    listeners = [ ListenerConfig(port=port) ],
    plugins = [ PluginConfig(path=mosq_paths.test_plugin('auth_plugin_extended_multiple')) ],
)
broker = MosquittoBroker(config=broker_config)
with broker:
    sock = mosq_test.do_client_connect(connect_packet, auth1_packet, timeout=20, port=port, connack_error="auth1")
    mosq_test.do_send_receive(sock, auth2_packet, connack_packet)
    sock.close()
