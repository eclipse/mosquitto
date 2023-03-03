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

    connect_packet = mosq_test.gen_connect("13-malformed-publish-v5", proto_ver=5)

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
    # qos > maximum qos
    publish_packet = mosq_test.gen_publish(topic="test/topic", qos=2, mid=1, proto_ver=5)
    do_test(publish_packet, mqtt5_rc.MQTT_RC_QOS_NOT_SUPPORTED, "qos > maximum qos")

    # retain not supported
    publish_packet = mosq_test.gen_publish(topic="test/topic", qos=0, retain=True, proto_ver=5, payload="a")
    do_test(publish_packet, mqtt5_rc.MQTT_RC_RETAIN_NOT_SUPPORTED, "retain not supported")
except mosq_test.TestError:
    pass
finally:
    broker.terminate()
    if mosq_test.wait_for_subprocess(broker):
        print("broker not terminated")
        if rc == 0: rc=1
    (stdo, stde) = broker.communicate()
    os.remove(conf_file)
    if rc:
        print(stde.decode('utf-8'))
        exit(rc)
