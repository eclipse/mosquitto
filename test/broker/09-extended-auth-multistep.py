#!/usr/bin/env python3

from mosq_test_helper import *

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("auth_plugin c/auth_plugin_extended_multiple.so\n")

port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
write_config(conf_file, port)

rc = 1

props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_METHOD, "mirror")
props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_DATA, "step1")
connect_packet = mosq_test.gen_connect("client-params-test", proto_ver=5, properties=props)

# Server to client
props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_METHOD, "mirror")
props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_DATA, "1pets")
auth1_packet = mosq_test.gen_auth(reason_code=mqtt5_rc.MQTT_RC_CONTINUE_AUTHENTICATION, properties=props)

# Client to server
props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_METHOD, "mirror")
props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_DATA, "supercalifragilisticexpialidocious")
auth2_packet = mosq_test.gen_auth(reason_code=mqtt5_rc.MQTT_RC_CONTINUE_AUTHENTICATION, properties=props)

props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_METHOD, "mirror")
connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5, properties=props)


broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

try:
    sock = mosq_test.do_client_connect(connect_packet, auth1_packet, timeout=20, port=port, connack_error="auth1")
    mosq_test.do_send_receive(sock, auth2_packet, connack_packet)

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

