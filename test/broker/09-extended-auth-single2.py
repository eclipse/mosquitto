#!/usr/bin/env python3

# Multi tests for extended auth with a single step - multiple plugins at once.
# * Error in plugin
# * No matching authentication method
# * Matching authentication method, but auth rejected
# * Matching authentication method, auth succeeds
# * Matching authentication method, auth succeeds, new auth data sent back to client


from mosq_test_helper import *

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("auth_plugin c/auth_plugin_extended_single.so\n")
        f.write("auth_plugin c/auth_plugin_extended_single2.so\n")

port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')


def do_test(suffix):
    write_config(conf_file, port)
    rc = 1
    # Single, error in plugin
    props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_METHOD, "error%s" % (suffix))
    connect1_packet = mosq_test.gen_connect("client-params-test1", proto_ver=5, properties=props)

    # Single, no matching authentication method
    props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_METHOD, "non-matching%s" % (suffix))
    connect2_packet = mosq_test.gen_connect("client-params-test2", proto_ver=5, properties=props)
    connack2_packet = mosq_test.gen_connack(rc=mqtt5_rc.MQTT_RC_BAD_AUTHENTICATION_METHOD, proto_ver=5, properties=None)

    # Single step, matching method, failure
    props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_METHOD, "single%s" % (suffix))
    props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_DATA, "baddata")
    connect3_packet = mosq_test.gen_connect("client-params-test3", proto_ver=5, properties=props)
    connack3_packet = mosq_test.gen_connack(rc=mqtt5_rc.MQTT_RC_NOT_AUTHORIZED, proto_ver=5, properties=None)

    # Single step, matching method, success
    props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_METHOD, "single%s" % (suffix))
    props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_DATA, "data")
    connect4_packet = mosq_test.gen_connect("client-params-test5", proto_ver=5, properties=props)
    props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_METHOD, "single%s" % (suffix))
    connack4_packet = mosq_test.gen_connack(rc=0, proto_ver=5, properties=props)

    # Single step, matching method, success, auth data back to client
    props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_METHOD, "mirror%s" % (suffix))
    props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_DATA, "somedata")
    connect5_packet = mosq_test.gen_connect("client-params-test6", proto_ver=5, properties=props)
    props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_METHOD, "mirror%s" % (suffix))
    props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_DATA, "atademos")
    connack5_packet = mosq_test.gen_connack(rc=0, proto_ver=5, properties=props)


    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    try:
        sock = mosq_test.do_client_connect(connect1_packet, b"", timeout=20, port=port)
        sock.close()

        sock = mosq_test.do_client_connect(connect2_packet, connack2_packet, timeout=20, port=port)
        sock.close()

        sock = mosq_test.do_client_connect(connect3_packet, connack3_packet, timeout=20, port=port)
        sock.close()

        sock = mosq_test.do_client_connect(connect4_packet, connack4_packet, timeout=20, port=port)
        sock.close()

        sock = mosq_test.do_client_connect(connect5_packet, connack5_packet, timeout=20, port=port)
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

do_test("")
do_test("2")
exit(0)

