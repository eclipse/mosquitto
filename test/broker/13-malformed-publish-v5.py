#!/usr/bin/env python3

# Test whether the broker handles malformed packets correctly - PUBLISH
# MQTTv5

from mosq_test_helper import *

rc = 1

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")
        f.write("maximum_qos 1\n")
        f.write("retain_available false\n")

def do_test(publish_packet, reason_code, error_string):
    global rc

    rc = 1

    keepalive = 10
    connect_packet = mosq_test.gen_connect("test", proto_ver=5, keepalive=keepalive)

    connack_props = mqtt5_props.gen_uint16_prop(mqtt5_props.PROP_TOPIC_ALIAS_MAXIMUM, 10)
    connack_props += mqtt5_props.gen_byte_prop(mqtt5_props.PROP_RETAIN_AVAILABLE, 0)
    connack_props += mqtt5_props.gen_uint16_prop(mqtt5_props.PROP_RECEIVE_MAXIMUM, 20)
    connack_props += mqtt5_props.gen_byte_prop(mqtt5_props.PROP_MAXIMUM_QOS, 1)

    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5, properties=connack_props, property_helper=False)

    mid = 0
    disconnect_packet = mosq_test.gen_disconnect(proto_ver=5, reason_code=reason_code)

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
    mosq_test.do_send_receive(sock, publish_packet, disconnect_packet, error_string=error_string)
    rc = 0


port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
write_config(conf_file, port)
broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

try:
    # mid == 0
    publish_packet = mosq_test.gen_publish(topic="test/topic", qos=1, mid=0, proto_ver=5)
    do_test(publish_packet, mqtt5_rc.MQTT_RC_PROTOCOL_ERROR, "mid == 0")

    # qos > 2
    publish_packet = mosq_test.gen_publish(topic="test/topic", qos=3, mid=1, proto_ver=5)
    do_test(publish_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "qos > 2")

    # qos > maximum qos
    publish_packet = mosq_test.gen_publish(topic="test/topic", qos=2, mid=1, proto_ver=5)
    do_test(publish_packet, mqtt5_rc.MQTT_RC_QOS_NOT_SUPPORTED, "qos > maximum qos")

    # retain not supported
    publish_packet = mosq_test.gen_publish(topic="test/topic", qos=0, retain=True, proto_ver=5, payload="a")
    do_test(publish_packet, mqtt5_rc.MQTT_RC_RETAIN_NOT_SUPPORTED, "retain not supported")

    # Incorrect property
    props = mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_SESSION_EXPIRY_INTERVAL, 0)
    publish_packet = mosq_test.gen_publish(topic="test/topic", qos=1, mid=1, proto_ver=5, properties=props)
    do_test(publish_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "Incorrect property")

    # Truncated packet, remaining length only
    publish_packet = struct.pack("!BB", 48, 0)
    do_test(publish_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "Truncated packet, remaining length only")

    # Truncated packet, empty topic
    publish_packet = struct.pack("!BBH", 48, 2, 0)
    do_test(publish_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "Truncated packet, empty topic")

    # Truncated packet, with topic, no properties
    publish_packet = struct.pack("!BBH1s", 48, 3, 1, b"a")
    do_test(publish_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "Truncated packet, with topic, no properties")

    # Truncated packet, with topic, no mid
    publish_packet = struct.pack("!BBH1s", 48+2, 3, 1, b"a")
    do_test(publish_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "Truncated packet, with topic, no mid")

    # Truncated packet, with topic, with mid, no properties
    publish_packet = struct.pack("!BBH1sH", 48+2, 5, 1, b"a", 1)
    do_test(publish_packet, mqtt5_rc.MQTT_RC_MALFORMED_PACKET, "Truncated packet, with topic, with mid, no properties")

    # Bad topic
    publish_packet = mosq_test.gen_publish(topic="#/test/topic", qos=1, mid=1, proto_ver=5)
    do_test(publish_packet, mqtt5_rc.MQTT_RC_PROTOCOL_ERROR, "Bad topic")
except mosq_test.TestError:
    pass
finally:
    broker.terminate()
    broker.wait()
    (stdo, stde) = broker.communicate()
    os.remove(conf_file)
    if rc:
        print(stde.decode('utf-8'))
        exit(rc)
