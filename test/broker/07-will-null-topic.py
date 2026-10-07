#!/usr/bin/env python3

import struct

from mosq_test_helper import *

def do_test(proto_ver):
    connect_packet = mqtt_packets.gen_connect("will-null-topic", will_topic="", will_payload=struct.pack("!4sB7s", b"will", 0, b"message"), proto_ver=proto_ver)

    if proto_ver == 5:
        connack_packet = mqtt_packets.gen_connack(rc=mqtt5_rc.PROTOCOL_ERROR, proto_ver=5)
    else:
        connack_packet = b""

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
    do_test(proto_ver=4)
    do_test(proto_ver=5)
