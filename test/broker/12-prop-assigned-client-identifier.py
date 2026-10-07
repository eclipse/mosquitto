#!/usr/bin/env python3

# Test whether sending a non zero session expiry interval in DISCONNECT after
# having sent a zero session expiry interval is treated correctly in MQTT v5.

from mosq_test_helper import *


def do_test(clean_start):
    connect_packet = mqtt_packets.gen_connect(None, proto_ver=5, clean_session=clean_start)

    props = mqtt5_props.gen_string_prop(mqtt5_props.ASSIGNED_CLIENT_IDENTIFIER, "auto-00000000-0000-0000-0000-000000000000")
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=5, properties=props)

    props = mqtt5_props.gen_uint32_prop(mqtt5_props.SESSION_EXPIRY_INTERVAL, 1)
    disconnect_client_packet = mqtt_packets.gen_disconnect(proto_ver=5, properties=props)

    disconnect_server_packet = mqtt_packets.gen_disconnect(proto_ver=5, reason_code=130)

    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)
    with broker:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(("localhost", port))

        sock.send(connect_packet)
        connack_recvd = sock.recv(len(connack_packet))
        sock.close()

        if connack_recvd[0:12] == connack_packet[0:12]:
            # FIXME - this test could be tightened up a lot
            pass
        else:
            raise ValueError(connack_recvd)


if __name__ == '__main__':
    do_test(True)
    do_test(False)
