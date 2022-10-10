#!/usr/bin/env python3

# Check for performance of processing user-property on CONNECT

from mosq_test_helper import *

def do_test():
    rc = 1
    props = mqtt5_props.gen_string_pair_prop(mqtt5_props.PROP_USER_PROPERTY, "key", "value")
    for i in range(0, 5000):
        props += mqtt5_props.gen_string_pair_prop(mqtt5_props.PROP_USER_PROPERTY, "key", "value")
    connect_packet_slow = mosq_test.gen_connect("connect-user-property", proto_ver=5, properties=props)
    connect_packet_fast = mosq_test.gen_connect("a"*65000, proto_ver=5)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    port = mosq_test.get_port()
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        t_start = time.monotonic()
        sock = mosq_test.do_client_connect(connect_packet_slow, connack_packet, port=port)
        t_stop = time.monotonic()
        sock.close()

        t_diff_slow = t_stop - t_start

        t_start = time.monotonic()
        sock = mosq_test.do_client_connect(connect_packet_fast, connack_packet, port=port)
        t_stop = time.monotonic()
        sock.close()

        t_diff_fast = t_stop - t_start
        # 20 is chosen as a factor that works in plain mode and running under
        # valgrind. The slow performance manifests as a factor of >100. Fast is <10.
        if t_diff_slow / t_diff_fast < 20:
            rc = 0
    except mosq_test.TestError:
        pass
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
exit(0)
