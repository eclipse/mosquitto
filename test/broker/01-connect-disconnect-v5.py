#!/usr/bin/env python3

# loop through the different v5 DISCONNECT reason_code/properties options.

from mosq_test_helper import *

rc = 0
port = mosq_test.get_port()

def disco_test(test, disconnect_packet):
    global rc

    connect1_packet = mqtt_packets.gen_connect("sub", proto_ver=5)
    connack1_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    mid = 1
    subscribe1_packet = mqtt_packets.gen_subscribe(mid, "failure", 0, proto_ver=5)
    suback1_packet = mqtt_packets.gen_suback(mid, 0, proto_ver=5)

    connect2_packet = mqtt_packets.gen_connect("connect-disconnect-test", proto_ver=5, will_topic="failure", will_payload=b"failure")
    connack2_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    sock1 = mosq_test.do_client_connect(connect1_packet, connack1_packet, port=port)
    mosq_test.do_send_receive(sock1, subscribe1_packet, suback1_packet, "suback1")


    sock2 = mosq_test.do_client_connect(connect2_packet, connack2_packet, port=port)
    sock2.send(disconnect_packet)
    sock2.close()

    # If this fails then we probably received the will
    mosq_test.do_ping(sock1)

    rc -= 1

def do_test():
    global rc

    rc = 4

    broker = MosquittoBroker(port=port)
    with broker:
        # No reason code, no properties, len=0
        disconnect_packet = mqtt_packets.gen_disconnect(proto_ver=5)
        disco_test("disco len=0", disconnect_packet)

        # Reason code, no properties, len=1
        disconnect_packet = mqtt_packets.gen_disconnect(proto_ver=5, reason_code=0)
        disco_test("disco len=1", disconnect_packet)

        # Reason code, empty properties, len=2
        disconnect_packet = mqtt_packets.gen_disconnect(proto_ver=5, reason_code=0, properties="")
        disco_test("disco len=2", disconnect_packet)

        # Reason code, one property, len>2
        props = mqtt5_props.gen_string_pair_prop(mqtt5_props.USER_PROPERTY, "key", "value")
        disconnect_packet = mqtt_packets.gen_disconnect(proto_ver=5, reason_code=0, properties=props)
        disco_test("disco len>2", disconnect_packet)

        assert rc == 0


if __name__ == '__main__':
    do_test()
