#!/usr/bin/env python3

# Test whether the broker handles malformed packets correctly - UNSUBSCRIBE
# MQTTv5

from mosq_test_helper import *

rc = 1

def do_test(unsubscribe_packet, reason_code, error_string, port):
    global rc

    rc = 1

    connect_packet = mosq_test.gen_connect("13-malformed-unsubscribe", proto_ver=5)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    mid = 0
    disconnect_packet = mosq_test.gen_disconnect(proto_ver=5, reason_code=reason_code)

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
    mosq_test.do_send_receive(sock, unsubscribe_packet, disconnect_packet, error_string=error_string)
    rc = 0


def all_tests(start_broker=False):
    global rc

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        # mid == 0
        unsubscribe_packet = mosq_test.gen_unsubscribe(topic="13-malformed-unsubscribe/test/topic", mid=0, proto_ver=5)
        do_test(unsubscribe_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "mid == 0", port)

        # command flags != 0x02
        unsubscribe_packet = mosq_test.gen_unsubscribe(topic="13-malformed-unsubscribe/test/topic", mid=1, proto_ver=5, cmd=160)
        do_test(unsubscribe_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "command flags != 0x02", port)

        # Incorrect property
        props = mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_SESSION_EXPIRY_INTERVAL, 0)
        unsubscribe_packet = mosq_test.gen_unsubscribe(topic="13-malformed-unsubscribe/test/topic", mid=1, proto_ver=5, properties=props)
        do_test(unsubscribe_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "Incorrect property", port)

        # Truncated packet, no mid
        unsubscribe_packet = struct.pack("!BB", 162, 0)
        do_test(unsubscribe_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "Truncated packet, no mid", port)

        # Truncated packet, no properties
        unsubscribe_packet = struct.pack("!BBH", 162, 2, 1)
        do_test(unsubscribe_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "Truncated packet, no properties", port)

        # Truncated packet, with properties field, no topic
        unsubscribe_packet = struct.pack("!BBHH", 162, 4, 1, 0)
        do_test(unsubscribe_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "Truncated packet, with properties field, no topic", port)

        # Truncated packet, with properties field, empty topic
        unsubscribe_packet = struct.pack("!BBHHH", 162, 5, 1, 0, 0)
        do_test(unsubscribe_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "Truncated packet, with properties field, empty topic", port)

        # Bad topic
        unsubscribe_packet = mosq_test.gen_unsubscribe(topic="#/13-malformed-unsubscribe/test/topic", mid=1, proto_ver=5)
        do_test(unsubscribe_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "Bad topic", port)
    except mosq_test.TestError:
        pass
    finally:
        if start_broker:
            broker.terminate()
            if mosq_test.wait_for_subprocess(broker):
                print("broker not terminated")
                if rc == 0: rc=1
            (stdo, stde) = broker.communicate()
            if rc:
                print(stde.decode('utf-8'))
                exit(rc)
        else:
            return rc


if __name__ == '__main__':
    all_tests(True)
