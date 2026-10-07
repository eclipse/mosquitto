#!/usr/bin/env python3

# Test whether a client subscribed to a topic receives its own message sent to that topic, for long topics.

from mosq_test_helper import *

def do_test(port, topic, succeeds):
    mid = 53
    connect_packet = mqtt_packets.gen_connect("02-subpub-qos0-long-topic")
    connack_packet = mqtt_packets.gen_connack(rc=0)

    subscribe_packet = mqtt_packets.gen_subscribe(mid, topic, 0)
    suback_packet = mqtt_packets.gen_suback(mid, 0)

    publish_packet = mqtt_packets.gen_publish(topic, qos=0, payload="message")

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)

    if succeeds:
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")
        mosq_test.do_send_receive(sock, publish_packet, publish_packet, "publish")
    else:
        try:
            mosq_test.do_send_receive(sock, subscribe_packet, b"", "suback")
            raise RuntimeError(topic)
        except BrokenPipeError:
            pass
    sock.close()


def all_tests():
    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)

    with broker:
        do_test(port, "/"*200, True) # 200 max hierarchy limit
        do_test(port, "abc/"*199+"d", True) # 200 max hierarchy limit, longer overall string than 200
        do_test(port, "/"*201, False) # Exceeds 200 max hierarchy limit
        do_test(port, "abc/"*201+"d", False) # Exceeds 200 max hierarchy limit, longer overall string than 200

if __name__ == '__main__':
    all_tests()
