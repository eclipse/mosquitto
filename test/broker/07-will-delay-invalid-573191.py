#!/usr/bin/env python3

# Test for https://bugs.eclipse.org/bugs/show_bug.cgi?id=573191
# Check under valgrind/asan for leaks.

from mosq_test_helper import *

def do_test():
    rc = 1

    mid = 1
    props = mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_WILL_DELAY_INTERVAL, 3)
    connect_packet = mosq_test.gen_connect("will-573191-test", proto_ver=5, will_topic="", will_properties=props)
    connack_packet = b""

    port = mosq_test.get_port()
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=30, port=port)
        sock.close()
        rc = 0
    finally:
        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1
        (stdo, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
            exit(rc)

do_test()
