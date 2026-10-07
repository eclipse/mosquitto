#!/usr/bin/env python3

# Multi tests for extended auth with a single step.
# * Error in plugin
# * No matching authentication method
# * Matching authentication method, but auth rejected
# * Matching authentication method, auth succeeds
# * Matching authentication method, auth succeeds, new auth data sent back to client


from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, PluginConfig
from mosquitto_broker import MosquittoBroker

# Single, error in plugin
props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "error")
connect1_packet = mqtt_packets.gen_connect("client-params-test1", proto_ver=5, properties=props)

# Single, no matching authentication method
props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "non-matching")
connect2_packet = mqtt_packets.gen_connect("client-params-test2", proto_ver=5, properties=props)
connack2_packet = mqtt_packets.gen_connack(rc=mqtt5_rc.BAD_AUTHENTICATION_METHOD, proto_ver=5, properties=None)

# Single step, matching method, failure
props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "single")
props += mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_DATA, "baddata")
connect3_packet = mqtt_packets.gen_connect("client-params-test3", proto_ver=5, properties=props)
connack3_packet = mqtt_packets.gen_connack(rc=mqtt5_rc.NOT_AUTHORIZED, proto_ver=5, properties=None)

# Single step, matching method, success
props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "single")
props += mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_DATA, "data")
connect4_packet = mqtt_packets.gen_connect("client-params-test5", proto_ver=5, properties=props)
props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "single")
connack4_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5, properties=props)

# Single step, matching method, success, auth data back to client
props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "mirror")
props += mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_DATA, "somedata")
connect5_packet = mqtt_packets.gen_connect("client-params-test6", proto_ver=5, properties=props)
props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "mirror")
props += mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_DATA, "atademos")
connack5_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5, properties=props)


port = mosq_test.get_port()
broker_config = BrokerConfig(
    listeners = [ ListenerConfig(port=port) ],
    plugins = [
        PluginConfig(path=mosq_paths.test_plugin('auth_plugin_extended_single'))
    ],
)
broker = MosquittoBroker(config=broker_config)
with broker:
    sock = None
    try:
        sock = mosq_test.do_client_connect(connect1_packet, b"", timeout=20, port=port)
        sock.close()
        raise RuntimeError("socket connection was not lost")
    except BrokenPipeError:
        pass

    sock = mosq_test.do_client_connect(connect2_packet, connack2_packet, timeout=20, port=port)
    sock.close()

    sock = mosq_test.do_client_connect(connect3_packet, connack3_packet, timeout=20, port=port)
    sock.close()

    sock = mosq_test.do_client_connect(connect4_packet, connack4_packet, timeout=20, port=port)
    sock.close()

    sock = mosq_test.do_client_connect(connect5_packet, connack5_packet, timeout=20, port=port)
    sock.close()
