#!/usr/bin/env python3

# What does the broker do if an MQTT v5 client doesn't respect max_inflight_messages?

from mosq_test_helper import *

def do_test(proto_ver):
    port = mosq_test.get_port()

    connect_packet = mqtt_packets.gen_connect("pub-qos2-inflight-exceeded", proto_ver=proto_ver)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    broker = MosquittoBroker(port=port)

    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port, timeout=10)

        for i in range(1, 21):
            publish_packet = mqtt_packets.gen_publish("pub/qos2/max/inflight/exceeded", qos=2, mid=i, payload="message", proto_ver=proto_ver)
            pubrec_packet = mqtt_packets.gen_pubrec(mid=i, proto_ver=proto_ver)
            mosq_test.do_send_receive(sock, publish_packet, pubrec_packet)

        i = 21
        publish_packet = mqtt_packets.gen_publish("pub/qos2/max/inflight/exceeded", qos=2, mid=i, payload="message", proto_ver=proto_ver)
        if proto_ver == 5:
            disconnect_packet = mqtt_packets.gen_disconnect(reason_code=mqtt5_rc.RECEIVE_MAXIMUM_EXCEEDED, proto_ver=proto_ver)
        else:
            disconnect_packet = b""
        try:
            mosq_test.do_send_receive(sock, publish_packet, disconnect_packet, "disconnect")
        except BrokenPipeError:
            pass
        sock.close()


if __name__ == "__main__":
    do_test(proto_ver=4)
    do_test(proto_ver=5)
