#!/usr/bin/env python3

# Publish a retained messages, check they are restored

from mosq_test_helper import *
persist_help = persist_module()

port, _ = mosq_test.get_port(2)
conf_file = os.path.basename(__file__).replace('.py', '.conf')
persist_help.write_config(conf_file, port)

rc = 1

persist_help.init(port)

topic1 = "test/retain1"
topic2 = "test/retain2"
topic3 = "test/retain3"
source_id = "persist-retain-v5-0"
qos = 0
payload2 = "retained message 2"
payload3 = "retained message 3"
proto_ver = 5
connect_packet = mqtt_packets.gen_connect(source_id, proto_ver=proto_ver, clean_session=True)
connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

publish1_packet = mqtt_packets.gen_publish(topic1, qos=qos, payload="retained message 1", retain=True, proto_ver=proto_ver)
publish2_packet = mqtt_packets.gen_publish(topic2, qos=qos, payload=payload2, retain=False, proto_ver=proto_ver)
publish3_packet = mqtt_packets.gen_publish(topic3, qos=qos, payload=payload3, retain=True, proto_ver=proto_ver)

mid = 1
subscribe_packet = mqtt_packets.gen_subscribe(mid, "#", 0, proto_ver=proto_ver)
suback_packet = mqtt_packets.gen_suback(mid, qos=0, proto_ver=proto_ver)

mid = 2
unsubscribe_packet = mqtt_packets.gen_unsubscribe(mid, "#", proto_ver=proto_ver)
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
    sock.send(publish1_packet)
    mosq_test.do_ping(sock)
    sock.send(publish2_packet) # Not retained
    mosq_test.do_ping(sock)
    sock.send(publish3_packet)
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
    mosq_test.receive_unordered(sock, publish1_packet, publish3_packet, "publish 1 / 3")
    mosq_test.do_ping(sock)

    (broker_terminate_rc, stde) = mosq_test.terminate_broker(broker)
    broker = None
    persist_help.check_counts(port, base_msgs=2, retain_msgs=2)

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
