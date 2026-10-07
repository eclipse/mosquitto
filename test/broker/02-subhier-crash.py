#!/usr/bin/env python3

# Test related to https://github.com/eclipse/mosquitto/issues/505

from mosq_test_helper import *

def test(port):
    connect_packet = mqtt_packets.gen_connect("subhier-crash")
    connack_packet = mqtt_packets.gen_connack(rc=0)

    mid = 1
    subscribe1_packet = mqtt_packets.gen_subscribe(mid, "topic/a", 0)
    suback1_packet = mqtt_packets.gen_suback(mid, 0)

    mid = 2
    subscribe2_packet = mqtt_packets.gen_subscribe(mid, "topic/b", 0)
    suback2_packet = mqtt_packets.gen_suback(mid, 0)

    mid = 3
    unsubscribe1_packet = mqtt_packets.gen_unsubscribe(mid, "topic/a")
    unsuback1_packet = mqtt_packets.gen_unsuback(mid)

    disconnect_packet = mqtt_packets.gen_disconnect()
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
    mosq_test.do_send_receive(sock, subscribe1_packet, suback1_packet, "suback 1")
    mosq_test.do_send_receive(sock, subscribe2_packet, suback2_packet, "suback 2")
    mosq_test.do_send_receive(sock, unsubscribe1_packet, unsuback1_packet, "unsuback")
    sock.send(disconnect_packet)
    sock.close()


def do_test():
    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)

    with broker:
        test(port)
        # Repeat test to check broker is still there
        test(port)


if __name__ == '__main__':
    do_test()
