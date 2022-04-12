#!/usr/bin/env python3

# Publish a retained messages, check they are restored, with properties attached

from mosq_test_helper import *
import sqlite_help

port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
sqlite_help.write_config(conf_file, port)

rc = 1

sqlite_help.init(port)

topic = "test/retainprop"
source_id = "persist-retain-properties-v5-0"
qos = 0
proto_ver = 5
connect_packet = mosq_test.gen_connect(source_id, proto_ver=proto_ver, clean_session=True)
connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

props = mqtt5_props.gen_byte_prop(mqtt5_props.PROP_PAYLOAD_FORMAT_INDICATOR, 1)
props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_CONTENT_TYPE, "plain/text")
props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_RESPONSE_TOPIC, "/dev/null")
#props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_CORRELATION_DATA, "2357289375902345")
props += mqtt5_props.gen_string_pair_prop(mqtt5_props.PROP_USER_PROPERTY, "name", "value")
props += mqtt5_props.gen_string_pair_prop(mqtt5_props.PROP_USER_PROPERTY, "name", "value")
props += mqtt5_props.gen_string_pair_prop(mqtt5_props.PROP_USER_PROPERTY, "name", "value")
props += mqtt5_props.gen_string_pair_prop(mqtt5_props.PROP_USER_PROPERTY, "name", "value")
publish_packet = mosq_test.gen_publish(topic, qos=qos, payload="retained message 1", retain=True, proto_ver=proto_ver, properties=props)

mid = 1
subscribe_packet = mosq_test.gen_subscribe(mid, "test/retainprop", 0, proto_ver=proto_ver)
suback_packet = mosq_test.gen_suback(mid, qos=0, proto_ver=proto_ver)

mid = 2
unsubscribe_packet = mosq_test.gen_unsubscribe(mid, "test/retainprop", proto_ver=proto_ver)
unsuback_packet = mosq_test.gen_unsuback(mid, proto_ver=proto_ver)

broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

try:
    # Connect client
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port)
    # Check no retained messages exist
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")
    # Ping will fail if a PUBLISH is received
    mosq_test.do_ping(sock)
    # Unsubscribe, so we don't receive the messages
    mosq_test.do_send_receive(sock, unsubscribe_packet, unsuback_packet, "unsuback")

    # Send some retained messages
    sock.send(publish_packet)
    mosq_test.do_ping(sock)
    sock.close()

    # Kill broker
    broker.terminate()
    broker_terminate_rc = 0
    if mosq_test.wait_for_subprocess(broker):
        print("broker not terminated")
        broker_terminate_rc = 1

    # Restart broker
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    # Connect client
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port)
    # Subscribe
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")
    # Check retained messages exist
    mosq_test.expect_packet(sock, "publish", publish_packet)
    mosq_test.do_ping(sock)

    rc = broker_terminate_rc
finally:
    if broker is not None:
        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated (2)")
            if rc == 0: rc=1
        (stdo, stde) = broker.communicate()
    os.remove(conf_file)
    rc += sqlite_help.cleanup(port)

    if rc:
        print(stde.decode('utf-8'))


exit(rc)
