#!/usr/bin/env python3

from mosq_test_helper import *
import sqlite3
import sqlite_help

port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
sqlite_help.write_config(conf_file, port)

rc = 1
keepalive = 10

sqlite_help.init(port)

client_id = "sqlite-cmsg-v3-1-1"
payload = "queued message 1"
payload_b = payload.encode("UTF-8")
qos = 1
topic = "client-msg/test"
source_id = "sqlite-cmsg-v3-1-1-helper"
proto_ver = 4

keepalive = 10
connect_packet = mosq_test.gen_connect(client_id, keepalive=keepalive, proto_ver=proto_ver, clean_session=False)
connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

mid = 1
subscribe_packet = mosq_test.gen_subscribe(mid, topic, qos, proto_ver=proto_ver)
suback_packet = mosq_test.gen_suback(mid, qos=qos, proto_ver=proto_ver)

connect2_packet = mosq_test.gen_connect(source_id, keepalive=keepalive, proto_ver=proto_ver)
connack2_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

mid = 18
publish_packet = mosq_test.gen_publish(topic, mid=mid, qos=qos, payload=payload, proto_ver=proto_ver)
puback_packet = mosq_test.gen_puback(mid=mid, proto_ver=proto_ver)

broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

con = None
try:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port)
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")
    sock.close()

    sock = mosq_test.do_client_connect(connect2_packet, connack2_packet, timeout=5, port=port)
    mosq_test.do_send_receive(sock, publish_packet, puback_packet, "puback")
    sock.close()

    broker.terminate()
    broker_terminate_rc = 0
    if mosq_test.wait_for_subprocess(broker):
        print("broker not terminated")
        broker_terminate_rc = 1
    (stdo, stde) = broker.communicate()
    broker = None

    con = sqlite3.connect(f"{port}/mosquitto.sqlite3")
    cur = con.cursor()
    sqlite_help.check_counts(cur, clients=1, client_msgs=1, base_msgs=1, retains=0, subscriptions=1)

    # Check client
    sqlite_help.check_client(cur, client_id, None, 0, 0, port, 0, 2, 1, -1, 0)

    # Check subscription
    sqlite_help.check_subscription(cur, client_id, topic, qos, 0)

    # Check stored message
    store_id = sqlite_help.check_store_msg(cur, 0, topic, payload_b, source_id, None, len(payload_b), mid, port, qos, 0)

    # Check client msg
    sqlite_help.check_client_msg(cur, client_id, store_id, 0, sqlite_help.dir_out, 1, qos, 0, sqlite_help.ms_queued)

    con.close()
    rc = broker_terminate_rc
finally:
    if broker is not None:
        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated (2)")
            if rc == 0: rc=1
        (stdo, stde) = broker.communicate()
    if con is not None:
        con.close()
    os.remove(conf_file)
    rc += sqlite_help.cleanup(port)

    if rc:
        print(stde.decode('utf-8'))


exit(rc)
