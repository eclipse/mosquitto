#!/usr/bin/env python3

# Test whether a PUBLISH to a topic with 65535 hierarchy characters fails
# This needs checking with MOSQ_USE_VALGRIND=1 to detect memory failures
# https://github.com/eclipse/mosquitto/issues/1412


from mosq_test_helper import *

def do_test(proto_ver):
    rc = 1
    mid = 19
    connect_packet = mqtt_packets.gen_connect("03-pub-long-test", proto_ver=proto_ver)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    publish_packet = mqtt_packets.gen_publish("/"*65535, qos=1, mid=mid, payload="message", proto_ver=proto_ver)

    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)

    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        if proto_ver == 4:
            try:
                mosq_test.do_send_receive(sock, publish_packet, b"", "puback")
            except BrokenPipeError:
                rc = 0
        else:
            disconnect_packet = mqtt_packets.gen_disconnect(proto_ver=5, reason_code=mqtt5_rc.MALFORMED_PACKET)
            mosq_test.do_send_receive(sock, publish_packet, disconnect_packet, "puback")
            rc = 0

        sock.close()
        assert rc == 0


if __name__ == '__main__':
    do_test(proto_ver=4)
    do_test(proto_ver=5)
