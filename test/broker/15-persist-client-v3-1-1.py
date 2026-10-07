#!/usr/bin/env python3

# Connect a client, check it is restored, clear the client, check it is not there.

from mosq_test_helper import *
persist_help = persist_module()

port, _ = mosq_test.get_port(2)
conf_file = os.path.basename(__file__).replace('.py', '.conf')
persist_help.write_config(conf_file, port)

rc = 1

persist_help.init(port)

client_id = "persist-client-v3-1-1"
proto_ver = 4

connect_packet = mqtt_packets.gen_connect(client_id, proto_ver=proto_ver, clean_session=False)
connack_packet1 = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)
connack_packet2 = mqtt_packets.gen_connack(rc=0, flags=1, proto_ver=proto_ver)

connect_packet_clean = mqtt_packets.gen_connect(client_id, proto_ver=proto_ver, clean_session=True)

broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

con = None
try:
    # Connect client
    sock = mosq_test.do_client_connect(connect_packet, connack_packet1, timeout=5, port=port, connack_error="connack 1")
    mosq_test.do_ping(sock)
    sock.close()

    # Connect client again, it should have a session
    sock = mosq_test.do_client_connect(connect_packet, connack_packet2, timeout=5, port=port, connack_error="connack 2")
    mosq_test.do_ping(sock)
    sock.close()

    # Kill broker
    (broker_terminate_rc, stde) = mosq_test.terminate_broker(broker)
    broker = None

    # Restart broker
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    # Connect client again, it should have a session
    sock = mosq_test.do_client_connect(connect_packet, connack_packet2, timeout=5, port=port, connack_error="connack 3")
    mosq_test.do_ping(sock)
    sock.close()

    # Clear the client
    sock = mosq_test.do_client_connect(connect_packet_clean, connack_packet1, timeout=5, port=port, connack_error="connack 4")
    mosq_test.do_ping(sock)
    sock.close()

    # Connect client, it should not have a session
    sock = mosq_test.do_client_connect(connect_packet_clean, connack_packet1, timeout=5, port=port, connack_error="connack 5")
    mosq_test.do_ping(sock)
    sock.close()

    # Kill broker
    (broker_terminate_rc, stde) = mosq_test.terminate_broker(broker)
    broker = None

    # Restart broker
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    # Connect client, it should not have a session
    sock = mosq_test.do_client_connect(connect_packet_clean, connack_packet1, timeout=5, port=port, connack_error="connack 6")
    mosq_test.do_ping(sock)
    sock.close()

    (broker_terminate_rc, stde) = mosq_test.terminate_broker(broker)
    broker = None
    persist_help.check_counts(port)

    rc = broker_terminate_rc
finally:
    if broker is not None:
        mosq_test.terminate_broker(broker)
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated (3)")
            if rc == 0: rc=1
    os.remove(conf_file)
    rc += persist_help.cleanup(port)

    if rc:
        print(mosq_test.broker_log(broker))


exit(rc)
