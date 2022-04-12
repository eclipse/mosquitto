#!/usr/bin/env python3

# Test whether a connection is denied if it provides just a username when it
# needs a username and password.

from mosq_test_helper import *

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("password_file %s\n" % (filename.replace('.conf', '.pwfile')))
        f.write("allow_anonymous false\n")


def do_test(proto_ver):
    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port)

    rc = 1
    connect_packet = mosq_test.gen_connect("connect-uname-test", username="user", proto_ver=proto_ver)
    if proto_ver == 5:
        connack_packet = mosq_test.gen_connack(rc=mqtt5_rc.MQTT_RC_NOT_AUTHORIZED, proto_ver=proto_ver, properties=None)
    else:
        connack_packet = mosq_test.gen_connack(rc=5, proto_ver=proto_ver)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
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
            print("proto_ver=%d" % (proto_ver))
            exit(rc)


do_test(proto_ver=4)
do_test(proto_ver=5)
exit(0)
