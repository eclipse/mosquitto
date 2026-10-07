#!/usr/bin/env python3

# Test whether sending an Authentication Method produces the correct response
# when no auth methods are defined.

from mosq_test_helper import *

def do_test():
    props = mqtt5_props.gen_string_prop(mqtt5_props.AUTHENTICATION_METHOD, "basic")
    connect_packet = mqtt_packets.gen_connect("connect-test", proto_ver=5, properties=props)
    connack_packet = mqtt_packets.gen_connack(rc=mqtt5_rc.BAD_AUTHENTICATION_METHOD, proto_ver=5, properties=None)

    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)
    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        sock.close()


if __name__ == '__main__':
    do_test()
