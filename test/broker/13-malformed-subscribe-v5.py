#!/usr/bin/env python3

# Test whether the broker handles malformed packets correctly - SUBSCRIBE
# MQTTv5

from mosq_test_helper import *

rc = 1

def do_test(subscribe_packet, reason_code, error_string, port):
    global rc
    rc = 1

    connect_packet = mosq_test.gen_connect("13-malformed-subscribe-v5", proto_ver=5)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    mid = 0
    disconnect_packet = mosq_test.gen_disconnect(proto_ver=5, reason_code=reason_code)

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
    mosq_test.do_send_receive(sock, subscribe_packet, disconnect_packet, error_string=error_string)
    rc = 0


def all_tests(start_broker=False):
    global rc
    port = mosq_test.get_port()

    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        # mid == 0
        subscribe_packet = mosq_test.gen_subscribe(topic="13-malformed-subscribe/test/topic", qos=1, mid=0, proto_ver=5)
        do_test(subscribe_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "mid == 0", port)

        # qos > 2
        subscribe_packet = mosq_test.gen_subscribe(topic="13-malformed-subscribe/test/topic", qos=3, mid=1, proto_ver=5)
        do_test(subscribe_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "qos > 2", port)

        # retain handling = 0x30
        subscribe_packet = mosq_test.gen_subscribe(topic="13-malformed-subscribe/test/topic", qos=0x30, mid=1, proto_ver=5)
        do_test(subscribe_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "retain handling = 0x30", port)

        # subscription options = 0xC0
        subscribe_packet = mosq_test.gen_subscribe(topic="13-malformed-subscribe/test/topic", qos=0xC0, mid=1, proto_ver=5)
        do_test(subscribe_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "subscription options = 0xC0", port)

        # command flags != 0x02
        subscribe_packet = mosq_test.gen_subscribe(topic="13-malformed-subscribe/test/topic", qos=1, mid=1, proto_ver=5, cmd=128)
        do_test(subscribe_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "command flags != 0x02", port)

        # Incorrect property
        props = mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_SESSION_EXPIRY_INTERVAL, 0)
        subscribe_packet = mosq_test.gen_subscribe(topic="13-malformed-subscribe/test/topic", qos=1, mid=1, proto_ver=5, properties=props)
        do_test(subscribe_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "Incorrect property", port)

        # Truncated packet, no mid
        subscribe_packet = struct.pack("!BB", 130, 0)
        do_test(subscribe_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "Truncated packet, no mid", port)

        # Truncated packet, no properties
        subscribe_packet = struct.pack("!BBH", 130, 2, 1)
        do_test(subscribe_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "Truncated packet, no properties", port)

        # Truncated packet, with properties field
        subscribe_packet = struct.pack("!BBHB", 130, 3, 1, 0)
        do_test(subscribe_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "Truncated packet, with properties field", port)

        # Truncated packet, with properties field, empty topic
        subscribe_packet = struct.pack("!BBHBH", 130, 5, 1, 0, 0)
        do_test(subscribe_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "Truncated packet, with properties field, empty topic", port)

        # Truncated packet, with properties field, empty topic, with qos
        subscribe_packet = struct.pack("!BBHBHB", 130, 6, 1, 0, 0, 1)
        do_test(subscribe_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "Truncated packet, with properties field, empty topic, with qos", port)

        # Truncated packet, with properties field, with topic, no qos
        subscribe_packet = struct.pack("!BBHBH1s", 130, 6, 1, 0, 1, b"a")
        do_test(subscribe_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "Truncated packet, with properties field, with topic, no qos", port)

        # Truncated packet, with properties field, with 1st topic and qos ok, second topic ok, no second qos
        subscribe_packet = struct.pack("!BBHHH1sBH1s", 130, 10, 1, 0, 1, b"a", 0, 1, b"b")
        do_test(subscribe_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "Truncated packet, with properties field, with 1st topic and qos ok, second topic ok, no second qos", port)

        # Bad topic
        subscribe_packet = mosq_test.gen_subscribe(topic="#/13-malformed-subscribe/test/topic", qos=1, mid=1, proto_ver=5)
        do_test(subscribe_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "Bad topic", port)

        # Subscription ID set to 0
        props = mqtt5_props.gen_varint_prop(mqtt5_props.PROP_SUBSCRIPTION_IDENTIFIER, 0)
        subscribe_packet = mosq_test.gen_subscribe(topic="13-malformed-subscribe/test/topic", qos=1, mid=1, proto_ver=5, properties=props)
        do_test(subscribe_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "Subscription ID set to 0", port)
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
