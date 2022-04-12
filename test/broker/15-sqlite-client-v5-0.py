#!/usr/bin/env python3

# Connect a single client with session expiry interval > 0 and check the
# persisted DB is correct

from mosq_test_helper import *
import sqlite3
import sqlite_help

port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
sqlite_help.write_config(conf_file, port)

rc = 1
keepalive = 10

sqlite_help.init(port)

keepalive = 10
props = mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_SESSION_EXPIRY_INTERVAL, 60)
props += mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_MAXIMUM_PACKET_SIZE, 10000)
connect_packet = mosq_test.gen_connect("sqlite-client-v5-0", keepalive=keepalive, proto_ver=5, properties=props)

props = mqtt5_props.gen_uint16_prop(mqtt5_props.PROP_TOPIC_ALIAS_MAXIMUM, 10)
props += mqtt5_props.gen_uint16_prop(mqtt5_props.PROP_RECEIVE_MAXIMUM, 20)
#props += mqtt5_props.gen_byte_prop(mqtt5_props.PROP_MAXIMUM_QOS, 1)
connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5, properties=props, property_helper=False)

connect_packet_clean = mosq_test.gen_connect("sqlite-client-v5-0-clean", keepalive=keepalive, proto_ver=5)

broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

con = None
try:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port, connack_error="connack 1")
    sock.close()

    sock = mosq_test.do_client_connect(connect_packet_clean, connack_packet, timeout=5, port=port, connack_error="connack 2")
    sock.close()

    broker.terminate()
    broker_terminate_rc = 0
    if mosq_test.wait_for_subprocess(broker):
        print("broker not terminated")
        broker_terminate_rc = 1
    (stdo, stde) = broker.communicate()
    broker = None

    # Verify sqlite db
    con = sqlite3.connect(f"{port}/mosquitto.sqlite3")
    cur = con.cursor()
    sqlite_help.check_counts(cur, clients=1, client_msgs=0, base_msgs=0, retains=0, subscriptions=0)

    # Check client
    sqlite_help.check_client(cur, "sqlite-client-v5-0", None, 0, 1, port, 10000, 2, 1, 60, 0)

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
