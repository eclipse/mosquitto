#!/usr/bin/env python3

# Test whether message parameters are passed to the plugin acl check function.

from mosq_test_helper import *

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("auth_plugin c/auth_plugin_delayed.so\n")
        f.write("allow_anonymous false\n")

def do_test(proto_ver):
    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port)

    rc = 1
    connect_packet = mosq_test.gen_connect("delayed-auth-test", username="delayed-username", password="good", proto_ver=proto_ver)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    connect_packet2 = mosq_test.gen_connect("delayed-auth-test", username="delayed-username", password="bad", proto_ver=proto_ver)
    if proto_ver == 5:
        connack_packet2 = mosq_test.gen_connack(rc=mqtt5_rc.MQTT_RC_NOT_AUTHORIZED, proto_ver=proto_ver, property_helper=False)
    else:
        connack_packet2 = mosq_test.gen_connack(rc=5, proto_ver=proto_ver)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)
        sock.close()
        sock = mosq_test.do_client_connect(connect_packet2, connack_packet2, timeout=20, port=port)
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

do_test(4)
do_test(5)
