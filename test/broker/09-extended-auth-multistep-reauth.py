#!/usr/bin/env python3

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig, PluginConfig
from mosquitto_broker import MosquittoBroker

# First auth
# ==========
props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "mirror")
props += mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_DATA, "step1")
connect1_packet = mqtt_packets.gen_connect("client-params-test", proto_ver=5, properties=props)

# Server to client
props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "mirror")
props += mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_DATA, "1pets")
auth1_1_packet = mqtt_packets.gen_auth(reason_code=mqtt5_rc.CONTINUE_AUTHENTICATION, properties=props)

# Client to server
props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "mirror")
props += mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_DATA, "supercalifragilisticexpialidocious")
auth1_2_packet = mqtt_packets.gen_auth(reason_code=mqtt5_rc.CONTINUE_AUTHENTICATION, properties=props)

props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "mirror")
connack1_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5, properties=props)

# Second auth
# ===========
props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "mirror")
props += mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_DATA, "step1")
reauth2_packet = mqtt_packets.gen_auth(reason_code=mqtt5_rc.REAUTHENTICATE, properties=props)

# Server to client
props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "mirror")
props += mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_DATA, "1pets")
auth2_1_packet = mqtt_packets.gen_auth(reason_code=mqtt5_rc.CONTINUE_AUTHENTICATION, properties=props)

# Client to server
props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "mirror")
props += mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_DATA, "supercalifragilisticexpialidocious")
auth2_2_packet = mqtt_packets.gen_auth(reason_code=mqtt5_rc.CONTINUE_AUTHENTICATION, properties=props)

props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "mirror")
auth2_3_packet = mqtt_packets.gen_auth(reason_code=0, properties=props)


# Third auth - bad due to different method
# ========================================
props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "badmethod")
props += mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_DATA, "step1")
reauth3_packet = mqtt_packets.gen_auth(reason_code=mqtt5_rc.REAUTHENTICATE, properties=props)

# Server to client
disconnect3_packet = mqtt_packets.gen_disconnect(reason_code=mqtt5_rc.PROTOCOL_ERROR, proto_ver=5)


port = mosq_test.get_port()
broker_config = BrokerConfig(
    listeners = [ ListenerConfig(port=port) ],
    plugins = [ PluginConfig(path=mosq_paths.test_plugin('auth_plugin_extended_multiple')) ],
)
broker = MosquittoBroker(config=broker_config)
with broker:
    sock = mosq_test.do_client_connect(connect1_packet, auth1_1_packet, timeout=20, port=port, connack_error="auth1")
    mosq_test.do_send_receive(sock, auth1_2_packet, connack1_packet, "connack1")
    mosq_test.do_ping(sock, "pingresp1")

    mosq_test.do_send_receive(sock, reauth2_packet, auth2_1_packet, "auth2_1")
    mosq_test.do_send_receive(sock, auth2_2_packet, auth2_3_packet, "auth2_3")
    mosq_test.do_ping(sock, "pingresp2")

    mosq_test.do_send_receive(sock, reauth3_packet, disconnect3_packet, "disconnect3")
    sock.close()
