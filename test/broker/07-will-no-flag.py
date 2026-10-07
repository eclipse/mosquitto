#!/usr/bin/env python3

# Test whether a connection is disconnected if it sets the will flag but does
# not provide a will payload.

from mosq_test_helper import *

def do_test(proto_ver):
    connect_packet = mqtt_packets.gen_connect("will-no-payload", will_topic="will/topic", will_qos=1, will_retain=True, proto_ver=proto_ver)
    b = list(struct.unpack("B"*len(connect_packet), connect_packet))

    bmod = b[0:len(b)-2]
    bmod[1] = bmod[1] - 2 # Reduce remaining length by two to remove final two payload length values

    connect_packet = struct.pack("B"*len(bmod), *bmod)
    connack_packet = mqtt_packets.gen_connack(mqtt5_rc.PROTOCOL_ERROR, proto_ver=5)

    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)
    with broker:
        rc = 1
        try:
            sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
            sock.close()
        except BrokenPipeError:
            rc = 0
        assert rc == 0


if __name__ == '__main__':
    do_test(proto_ver=4)
    do_test(proto_ver=5)
