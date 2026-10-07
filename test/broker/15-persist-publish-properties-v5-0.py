#!/usr/bin/env python3

# Publish a retained messages, check they are restored, with properties attached

from mosq_test_helper import *
persist_help = persist_module()

port, _ = mosq_test.get_port(2)
conf_file = os.path.basename(__file__).replace('.py', '.conf')
persist_help.write_config(conf_file, port)

rc = 1

persist_help.init(port)

topic = "test/retainprop"
source_id = "persist-retain-properties-v5-0"
qos = 0
proto_ver = 5
connect_packet = mqtt_packets.gen_connect(source_id, proto_ver=proto_ver, clean_session=True)
connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

base_props = mqtt5_props.gen_byte_prop(mqtt5_props.PAYLOAD_FORMAT_INDICATOR, 1)
base_props += mqtt5_props.gen_string_prop(mqtt5_props.CONTENT_TYPE, "plain/text")
base_props += mqtt5_props.gen_string_prop(mqtt5_props.RESPONSE_TOPIC, "/dev/null")
base_props += mqtt5_props.gen_string_prop(mqtt5_props.CORRELATION_DATA, "2357289375902345")
base_props += mqtt5_props.gen_string_pair_prop(mqtt5_props.USER_PROPERTY, "name", "value4")
base_props += mqtt5_props.gen_string_pair_prop(mqtt5_props.USER_PROPERTY, "name", "value3")
base_props += mqtt5_props.gen_string_pair_prop(mqtt5_props.USER_PROPERTY, "name", "value2")
base_props += mqtt5_props.gen_string_pair_prop(mqtt5_props.USER_PROPERTY, "name", "value1")
props = base_props + mqtt5_props.gen_uint32_prop(mqtt5_props.MESSAGE_EXPIRY_INTERVAL, 60)
publish_packet = mqtt_packets.gen_publish(topic, qos=qos, payload="retained message 1", retain=True, proto_ver=proto_ver, properties=props)

mid = 1
subscribe_packet = mqtt_packets.gen_subscribe(mid, "test/retainprop", 0, proto_ver=proto_ver)
suback_packet = mqtt_packets.gen_suback(mid, qos=0, proto_ver=proto_ver)

mid = 2
unsubscribe_packet = mqtt_packets.gen_unsubscribe(mid, "test/retainprop", proto_ver=proto_ver)
unsuback_packet = mqtt_packets.gen_unsuback(mid, proto_ver=proto_ver)

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
    (broker_terminate_rc, stde) = mosq_test.terminate_broker(broker)
    broker = None

    # Restart broker
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    # Connect client
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port)
    # Subscribe
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")
    # Check retained messages exist
    packet = sock.recv(len(publish_packet))
    for i in range(60, 1, -1):
        props = base_props + mqtt5_props.gen_uint32_prop(mqtt5_props.MESSAGE_EXPIRY_INTERVAL, i)
        publish_packet = mqtt_packets.gen_publish(topic, qos=qos, payload="retained message 1", retain=True, proto_ver=proto_ver, properties=props)
        if packet == publish_packet:
            rc = 0
            break

    mosq_test.do_ping(sock)

    (broker_terminate_rc, stde) = mosq_test.terminate_broker(broker)
    broker = None
    persist_help.check_counts(port, base_msgs=1, retain_msgs=1)

    if rc == 0:
        rc = broker_terminate_rc
finally:
    if broker is not None:
        mosq_test.terminate_broker(broker)
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated (2)")
            if rc == 0: rc=1
    os.remove(conf_file)
    rc += persist_help.cleanup(port)

    if rc:
        print(mosq_test.broker_log(broker))


exit(rc)
