#!/usr/bin/env python3

# Test whether sending an Authentication Method produces the correct response
# when no auth methods are defined.

from mosq_test_helper import *

def do_test(start_broker):
    rc = 1
    props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_AUTHENTICATION_METHOD, "basic")
    connect_packet = mosq_test.gen_connect("connect-test", proto_ver=5, properties=props)
    connack_packet = mosq_test.gen_connack(rc=mqtt5_rc.MQTT_RC_BAD_AUTHENTICATION_METHOD, proto_ver=5, properties=None)

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        sock.close()
        rc = 0
    except mosq_test.TestError:
        pass
    finally:
        if start_broker:
            broker.terminate()
            if mosq_test.wait_for_subprocess(broker):
                print("broker not terminated")
                if rc == 0: rc=1
            (stdo, stde) = broker.communicate()
            if rc:
                print(stde.decode('utf-8'))
                exit(rc)
        else:
            return rc

def all_tests(start_broker=False):
    return do_test(start_broker)

if __name__ == '__main__':
    all_tests(True)
