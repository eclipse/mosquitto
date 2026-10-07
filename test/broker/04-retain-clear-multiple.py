#!/usr/bin/env python3

# Exercise multi-level retain clearing

from mosq_test_helper import *

def send_retain(port, topic, payload):
    connect_packet = mqtt_packets.gen_connect("retain-clear-test")
    connack_packet = mqtt_packets.gen_connack(rc=0)

    publish_packet = mqtt_packets.gen_publish(topic, qos=1, mid=1, payload=payload, retain=True)
    puback_packet = mqtt_packets.gen_puback(mid=1)

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=4, port=port)
    mosq_test.do_send_receive(sock, publish_packet, puback_packet, f"set retain {topic}")
    sock.close()

def do_test():
    connect_packet = mqtt_packets.gen_connect("retain-clear-test")
    connack_packet = mqtt_packets.gen_connack(rc=0)

    subscribe_packet = mqtt_packets.gen_subscribe(1, "#", 0)
    suback_packet = mqtt_packets.gen_suback(1, 0)

    retain1_packet = mqtt_packets.gen_publish("1/2/3/4/5/6/7", qos=0, payload="retained message", retain=True)
    retain2_packet = mqtt_packets.gen_publish("1/2/3/4", qos=0, payload="retained message", retain=True)
    retain3_packet = mqtt_packets.gen_publish("1", qos=0, payload="retained message", retain=True)

    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)
    with broker:
        send_retain(port, "1/2/3/4/5/6/7", "retained message")
        send_retain(port, "1/2/3/4", "retained message")
        send_retain(port, "1", "retained message")

        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")
        mosq_test.expect_packet(sock, "retain3", retain3_packet)
        mosq_test.expect_packet(sock, "retain2", retain2_packet)
        mosq_test.expect_packet(sock, "retain1", retain1_packet)
        sock.close()

        send_retain(port, "1/2/3/4", None)

        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")
        mosq_test.expect_packet(sock, "retain3", retain3_packet)
        mosq_test.expect_packet(sock, "retain1", retain1_packet)
        sock.close()

        send_retain(port, "1/2/3/4/5/6/7", None)

        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")
        mosq_test.expect_packet(sock, "retain3", retain3_packet)
        sock.close()

        send_retain(port, "1", None)

        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")
        mosq_test.do_ping(sock)
        sock.close()


if __name__ == '__main__':
    do_test()
