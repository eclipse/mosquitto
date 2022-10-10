#!/usr/bin/env python3

from mosq_test_helper import *

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("port %d\n" % (port))
        f.write("auth_plugin c/auth_plugin_extended_reauth.so\n")

port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
write_config(conf_file, port)

rc = 1

# First authentication succeeds
props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_METHOD, "repeat")
props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_DATA, "repeat")
connect_packet = mosq_test.gen_connect("client-params-test", proto_ver=5, properties=props)

props = mqtt5_props.gen_uint16_prop(mqtt5_props.PROP_TOPIC_ALIAS_MAXIMUM, 10)
props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_METHOD, "repeat")
props += mqtt5_props.gen_uint16_prop(mqtt5_props.PROP_RECEIVE_MAXIMUM, 20)
connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5, properties=props, property_helper=False)

# Reauthentication fails
props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_METHOD, "repeat")
props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_DATA, "repeat")
auth_packet = mosq_test.gen_auth(reason_code=mqtt5_rc.MQTT_RC_REAUTHENTICATE, properties=props)
disconnect_packet = mosq_test.gen_disconnect(reason_code=mqtt5_rc.MQTT_RC_NOT_AUTHORIZED, proto_ver=5)

broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

try:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)
    mosq_test.do_send_receive(sock, auth_packet, disconnect_packet)
    sock.close()

    rc = 0
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

