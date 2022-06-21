#!/usr/bin/env python3

# Publish a retained messages, check they are restored

from mosq_test_helper import *
import sqlite_help

port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
sqlite_help.write_config(conf_file, port)

rc = 1

sqlite_help.init(port)

topic1 = "test/retain1"
topic2 = "test/retain2"
source_id = "persist-retain-v5-0"
qos = 0
payload1 = "retained message 1"
payload2 = "retained message 2"
proto_ver = 5
connect_packet = mosq_test.gen_connect(source_id, proto_ver=proto_ver, clean_session=True)
connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

publish1_packet = mosq_test.gen_publish(topic1, qos=qos, payload=payload1, retain=True, proto_ver=proto_ver)
publish2_packet = mosq_test.gen_publish(topic2, qos=qos, payload=payload2, retain=True, proto_ver=proto_ver)

publish2_clear_packet = mosq_test.gen_publish(topic2, qos=qos, payload="", retain=True, proto_ver=proto_ver)
publish2_clear_echo = mosq_test.gen_publish(topic2, qos=qos, payload="", retain=False, proto_ver=proto_ver)

mid = 1
subscribe_packet = mosq_test.gen_subscribe(mid, "#", 0, proto_ver=proto_ver)
suback_packet = mosq_test.gen_suback(mid, qos=0, proto_ver=proto_ver)

mid = 2
unsubscribe_packet = mosq_test.gen_unsubscribe(mid, "#", proto_ver=proto_ver)
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
    sock.send(publish1_packet)
    mosq_test.do_ping(sock)
    sock.send(publish2_packet)
    mosq_test.do_ping(sock)
    sock.close()

    # Connect client
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port)
    # Subscribe
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")
    # Check retained messages exist
    mosq_test.receive_unordered(sock, publish1_packet, publish2_packet, "publish 1 / 2")
    mosq_test.do_ping(sock)

    # Clear retained (and wait for the publish to avoid race condition)
    mosq_test.do_send_receive(sock, publish2_clear_packet, publish2_clear_echo, "clear retain flag")

    # Kill broker
    broker.terminate()
    broker.wait()

    # Restart broker
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    # Connect client
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port)
    # Subscribe
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")
    # Check single retained message exists
    mosq_test.expect_packet(sock, "publish 1", publish1_packet)
    mosq_test.do_ping(sock)

    rc = 0
finally:
    if broker is not None:
        broker.terminate()
        broker.wait()
        (stdo, stde) = broker.communicate()
    os.remove(conf_file)
    rc += sqlite_help.cleanup(port)

    if rc:
        print(stde.decode('utf-8'))


exit(rc)
