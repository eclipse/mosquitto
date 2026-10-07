#!/usr/bin/env python3

# MQTT v5 session takeover test

from mosq_test_helper import *

port = mosq_test.get_port()
broker = MosquittoBroker(port=port)
with broker:
    connect_packet = mqtt_packets.gen_connect("take-over", proto_ver=5)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)
    disconnect_packet = mqtt_packets.gen_disconnect(reason_code=mqtt5_rc.SESSION_TAKEN_OVER, proto_ver=5)

    sock1 = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
    sock2 = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
    mosq_test.expect_packet(sock1, "disconnect", disconnect_packet)
    mosq_test.do_ping(sock2)

    sock2.close()
    sock1.close()
