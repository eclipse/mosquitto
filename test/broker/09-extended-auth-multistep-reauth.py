#!/usr/bin/env python3

from mosq_test_helper import *

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")
        f.write("auth_plugin c/auth_plugin_extended_multiple.so\n")

port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
write_config(conf_file, port)

rc = 1

# First auth
# ==========
props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_METHOD, "mirror")
props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_DATA, "step1")
connect1_packet = mosq_test.gen_connect("client-params-test", proto_ver=5, properties=props)

# Server to client
props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_METHOD, "mirror")
props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_DATA, "1pets")
auth1_1_packet = mosq_test.gen_auth(reason_code=mqtt5_rc.MQTT_RC_CONTINUE_AUTHENTICATION, properties=props)

# Client to server
props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_METHOD, "mirror")
props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_DATA, "supercalifragilisticexpialidocious")
auth1_2_packet = mosq_test.gen_auth(reason_code=mqtt5_rc.MQTT_RC_CONTINUE_AUTHENTICATION, properties=props)

props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_METHOD, "mirror")
connack1_packet = mosq_test.gen_connack(rc=0, proto_ver=5, properties=props)

# Second auth
# ===========
props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_METHOD, "mirror")
props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_DATA, "step1")
reauth2_packet = mosq_test.gen_auth(reason_code=mqtt5_rc.MQTT_RC_REAUTHENTICATE, properties=props)

# Server to client
props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_METHOD, "mirror")
props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_DATA, "1pets")
auth2_1_packet = mosq_test.gen_auth(reason_code=mqtt5_rc.MQTT_RC_CONTINUE_AUTHENTICATION, properties=props)

# Client to server
props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_METHOD, "mirror")
props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_DATA, "supercalifragilisticexpialidocious")
auth2_2_packet = mosq_test.gen_auth(reason_code=mqtt5_rc.MQTT_RC_CONTINUE_AUTHENTICATION, properties=props)

props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_METHOD, "mirror")
auth2_3_packet = mosq_test.gen_auth(reason_code=0, properties=props)


# Third auth - bad due to different method
# ========================================
props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_METHOD, "badmethod")
props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_DATA, "step1")
reauth3_packet = mosq_test.gen_auth(reason_code=mqtt5_rc.MQTT_RC_REAUTHENTICATE, properties=props)

# Server to client
disconnect3_packet = mosq_test.gen_disconnect(reason_code=mqtt5_rc.MQTT_RC_PROTOCOL_ERROR, proto_ver=5)


broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

try:
    sock = mosq_test.do_client_connect(connect1_packet, auth1_1_packet, timeout=20, port=port, connack_error="auth1")
    mosq_test.do_send_receive(sock, auth1_2_packet, connack1_packet, "connack1")
    mosq_test.do_ping(sock, "pingresp1")

    mosq_test.do_send_receive(sock, reauth2_packet, auth2_1_packet, "auth2_1")
    mosq_test.do_send_receive(sock, auth2_2_packet, auth2_3_packet, "auth2_3")
    mosq_test.do_ping(sock, "pingresp2")

    mosq_test.do_send_receive(sock, reauth3_packet, disconnect3_packet, "disconnect3")

    rc = 0

    sock.close()
except mosq_test.TestError:
    pass
finally:
    os.remove(conf_file)
    broker.terminate()
    if mosq_test.wait_for_subprocess(broker):
        print("broker not terminated")
        if rc == 0: rc=1
    (stdo, stde) = broker.communicate()
    if rc:
        print(stde.decode('utf-8'))


exit(rc)

