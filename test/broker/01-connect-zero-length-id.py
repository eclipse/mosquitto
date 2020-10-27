#!/usr/bin/env python3

# Test whether a CONNECT with a zero length client id results in the correct behaviour.

# MQTT v3.1.1 - zero length is allowed, unless allow_zero_length_clientid is false, and unless clean_start is False.
# MQTT v5.0 - zero length is allowed, unless allow_zero_length_clientid is false

from mosq_test_helper import *

def write_config(filename, port1, port2, per_listener, allow_zero):
    with open(filename, 'w') as f:
        f.write("per_listener_settings %s\n" % (per_listener))
        f.write("listener %d\n" % (port2))
        f.write("allow_anonymous true\n")
        if allow_zero != "":
            f.write("allow_zero_length_clientid %s\n" % (allow_zero))
        f.write("listener %d\n" % (port1))
        f.write("allow_anonymous true\n")
        if allow_zero != "":
            f.write("allow_zero_length_clientid %s\n" % (allow_zero))


def do_test(per_listener, proto_ver, clean_start, allow_zero, client_port, expect_fail):
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port1, port2, per_listener, allow_zero)

    rc = 1
    keepalive = 10
    connect_packet = mosq_test.gen_connect("", keepalive=keepalive, proto_ver=proto_ver, clean_session=clean_start)
    if proto_ver == 4:
        if expect_fail == True:
            connack_packet = mosq_test.gen_connack(rc=2, proto_ver=proto_ver)
        else:
            connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)
    else:
        if expect_fail == True:
            connack_packet = mosq_test.gen_connack(rc=128, proto_ver=proto_ver, properties=None)
        else:
            props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_ASSIGNED_CLIENT_IDENTIFIER, "auto-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
            connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver, properties=props)
            # Remove the "xxxx" part - this means the front part of the packet
            # is correct (so remaining length etc. is correct), but we don't
            # need to match against the random id.
            connack_packet = connack_packet[:-39]

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port1, use_conf=True)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=client_port)
        sock.close()
        rc = 0
    except mosq_test.TestError:
        pass
    finally:
        broker.terminate()
        broker.wait()
        (stdo, stde) = broker.communicate()
        os.remove(conf_file)
        if rc:
            print(stde.decode('utf-8'))
            print("per_listener:%s proto_ver:%d client_port:%d clean_start:%d allow_zero:%s" % (per_listener, proto_ver, client_port, clean_start, allow_zero))
            print("port1:%d port2:%d" % (port1, port2))
            exit(rc)


(port1, port2) = mosq_test.get_port(2)

test_v4 = True
test_v5 = True

if test_v4 == True:
    do_test(per_listener="false", proto_ver=4, client_port=port1, clean_start=True, allow_zero="true", expect_fail=False)
    do_test(per_listener="false", proto_ver=4, client_port=port1, clean_start=True, allow_zero="false", expect_fail=True)
    do_test(per_listener="false", proto_ver=4, client_port=port1, clean_start=False, allow_zero="true", expect_fail=True)
    do_test(per_listener="false", proto_ver=4, client_port=port1, clean_start=False, allow_zero="false", expect_fail=True)
    do_test(per_listener="true", proto_ver=4, client_port=port1, clean_start=True, allow_zero="true", expect_fail=False)
    do_test(per_listener="true", proto_ver=4, client_port=port1, clean_start=True, allow_zero="false", expect_fail=True)
    do_test(per_listener="true", proto_ver=4, client_port=port1, clean_start=False, allow_zero="true", expect_fail=True)
    do_test(per_listener="true", proto_ver=4, client_port=port1, clean_start=False, allow_zero="false", expect_fail=True)

    do_test(per_listener="false", proto_ver=4, client_port=port2, clean_start=True, allow_zero="true", expect_fail=False)
    do_test(per_listener="false", proto_ver=4, client_port=port2, clean_start=True, allow_zero="false", expect_fail=True)
    do_test(per_listener="false", proto_ver=4, client_port=port2, clean_start=False, allow_zero="true", expect_fail=True)
    do_test(per_listener="false", proto_ver=4, client_port=port2, clean_start=False, allow_zero="false", expect_fail=True)
    do_test(per_listener="true", proto_ver=4, client_port=port2, clean_start=True, allow_zero="true", expect_fail=False)
    do_test(per_listener="true", proto_ver=4, client_port=port2, clean_start=True, allow_zero="false", expect_fail=True)
    do_test(per_listener="true", proto_ver=4, client_port=port2, clean_start=False, allow_zero="true", expect_fail=True)
    do_test(per_listener="true", proto_ver=4, client_port=port2, clean_start=False, allow_zero="false", expect_fail=True)

    do_test(per_listener="false", proto_ver=4, client_port=port1, clean_start=True, allow_zero="", expect_fail=False)
    do_test(per_listener="false", proto_ver=4, client_port=port1, clean_start=False, allow_zero="", expect_fail=True)
    do_test(per_listener="true", proto_ver=4, client_port=port1, clean_start=True, allow_zero="", expect_fail=False)
    do_test(per_listener="true", proto_ver=4, client_port=port1, clean_start=False, allow_zero="", expect_fail=True)

    do_test(per_listener="false", proto_ver=4, client_port=port2, clean_start=True, allow_zero="", expect_fail=False)
    do_test(per_listener="false", proto_ver=4, client_port=port2, clean_start=False, allow_zero="", expect_fail=True)
    do_test(per_listener="true", proto_ver=4, client_port=port2, clean_start=True, allow_zero="", expect_fail=False)
    do_test(per_listener="true", proto_ver=4, client_port=port2, clean_start=False, allow_zero="", expect_fail=True)

if test_v5 == True:
    do_test(per_listener="false", proto_ver=5, client_port=port1, clean_start=True, allow_zero="true", expect_fail=False)
    do_test(per_listener="false", proto_ver=5, client_port=port1, clean_start=True, allow_zero="false", expect_fail=True)
    do_test(per_listener="false", proto_ver=5, client_port=port1, clean_start=False, allow_zero="true", expect_fail=False)
    do_test(per_listener="false", proto_ver=5, client_port=port1, clean_start=False, allow_zero="false", expect_fail=True)
    do_test(per_listener="true", proto_ver=5, client_port=port1, clean_start=True, allow_zero="true", expect_fail=False)
    do_test(per_listener="true", proto_ver=5, client_port=port1, clean_start=True, allow_zero="false", expect_fail=True)
    do_test(per_listener="true", proto_ver=5, client_port=port1, clean_start=False, allow_zero="true", expect_fail=False)
    do_test(per_listener="true", proto_ver=5, client_port=port1, clean_start=False, allow_zero="false", expect_fail=True)

    do_test(per_listener="false", proto_ver=5, client_port=port2, clean_start=True, allow_zero="true", expect_fail=False)
    do_test(per_listener="false", proto_ver=5, client_port=port2, clean_start=True, allow_zero="false", expect_fail=True)
    do_test(per_listener="false", proto_ver=5, client_port=port2, clean_start=False, allow_zero="true", expect_fail=False)
    do_test(per_listener="false", proto_ver=5, client_port=port2, clean_start=False, allow_zero="false", expect_fail=True)
    do_test(per_listener="true", proto_ver=5, client_port=port2, clean_start=True, allow_zero="true", expect_fail=False)
    do_test(per_listener="true", proto_ver=5, client_port=port2, clean_start=True, allow_zero="false", expect_fail=True)
    do_test(per_listener="true", proto_ver=5, client_port=port2, clean_start=False, allow_zero="true", expect_fail=False)
    do_test(per_listener="true", proto_ver=5, client_port=port2, clean_start=False, allow_zero="false", expect_fail=True)

    do_test(per_listener="false", proto_ver=5, client_port=port1, clean_start=True, allow_zero="", expect_fail=False)
    do_test(per_listener="false", proto_ver=5, client_port=port1, clean_start=False, allow_zero="", expect_fail=False)
    do_test(per_listener="true", proto_ver=5, client_port=port1, clean_start=True, allow_zero="", expect_fail=False)
    do_test(per_listener="true", proto_ver=5, client_port=port1, clean_start=False, allow_zero="", expect_fail=False)

    do_test(per_listener="false", proto_ver=5, client_port=port2, clean_start=True, allow_zero="", expect_fail=False)
    do_test(per_listener="false", proto_ver=5, client_port=port2, clean_start=False, allow_zero="", expect_fail=False)
    do_test(per_listener="true", proto_ver=5, client_port=port2, clean_start=True, allow_zero="", expect_fail=False)
    do_test(per_listener="true", proto_ver=5, client_port=port2, clean_start=False, allow_zero="", expect_fail=False)

exit(0)
