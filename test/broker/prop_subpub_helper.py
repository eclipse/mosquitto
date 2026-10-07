#!/usr/bin/env python3

# Test whether a client subscribed to a topic receives its own message sent to that topic.
# Does a given property get sent through?
# MQTT v5

from mosq_test_helper import *

def prop_subpub_helper(test_name, props_out, props_in, expect_proto_error=False):
    rc = 1
    mid = 53
    connect_packet = mqtt_packets.gen_connect(test_name, proto_ver=5)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5)

    subscribe_packet = mqtt_packets.gen_subscribe(mid, "%s/subpub/qos0" % (test_name), 0, proto_ver=5)
    suback_packet = mqtt_packets.gen_suback(mid, 0, proto_ver=5)

    publish_packet_out = mqtt_packets.gen_publish("%s/subpub/qos0" % (test_name), qos=0, payload="message", proto_ver=5, properties=props_out)

    publish_packet_expected = mqtt_packets.gen_publish("%s/subpub/qos0" % (test_name), qos=0, payload="message", proto_ver=5, properties=props_in)

    disconnect_packet = mqtt_packets.gen_disconnect(reason_code=mqtt5_rc.PROTOCOL_ERROR, proto_ver=5)

    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)
    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)

        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")
        if expect_proto_error:
            mosq_test.do_send_receive(sock, publish_packet_out, disconnect_packet, "publish")
        else:
            mosq_test.do_send_receive(sock, publish_packet_out, publish_packet_expected, "publish")
        sock.close()
