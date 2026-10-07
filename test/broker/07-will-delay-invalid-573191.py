#!/usr/bin/env python3

# Test for https://bugs.eclipse.org/bugs/show_bug.cgi?id=573191
# Check under valgrind/asan for leaks.

from mosq_test_helper import *

def do_test():
    props = mqtt5_props.gen_uint32_prop(mqtt5_props.WILL_DELAY_INTERVAL, 3)
    connect_packet = mqtt_packets.gen_connect("will-573191-test", proto_ver=5, will_topic="", will_properties=props)
    connack_packet = mqtt_packets.gen_connack(rc=mqtt5_rc.PROTOCOL_ERROR, proto_ver=5)

    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)
    with broker:
        rc = 1
        try:
            sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=30, port=port)
            sock.close()
        except BrokenPipeError:
            rc = 0
        assert rc == 0


if __name__ == '__main__':
    do_test()
