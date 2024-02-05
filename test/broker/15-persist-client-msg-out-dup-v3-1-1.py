#!/usr/bin/env python3

from mosq_test_helper import *
persist_help = persist_module()

port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
persist_help.write_config(conf_file, port)

rc = 1
keepalive = 10

persist_help.init(port)

client_id = "persist-cmsg-out-dup-v3-1-1"
payload = "queued message 1"
payload_b = payload.encode("UTF-8")
qos = 2
topic = "client-msg/test"
source_id = "persist-cmsg-v3-1-1-helper"
proto_ver = 4

keepalive = 10
connect1_packet = mosq_test.gen_connect(client_id, keepalive=keepalive, proto_ver=proto_ver, clean_session=False)
connack1_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)
connack1_packet2 = mosq_test.gen_connack(rc=0, proto_ver=proto_ver, flags=1)

mid = 1
subscribe_packet = mosq_test.gen_subscribe(mid, topic, qos, proto_ver=proto_ver)
suback_packet = mosq_test.gen_suback(mid, qos=qos, proto_ver=proto_ver)

connect2_packet = mosq_test.gen_connect(source_id, keepalive=keepalive, proto_ver=proto_ver)
connack2_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

source_mid = 18
publish_packet = mosq_test.gen_publish(topic, mid=source_mid, qos=qos, payload=payload, proto_ver=proto_ver)
pubrec_packet = mosq_test.gen_pubrec(mid=source_mid, proto_ver=proto_ver)
pubrel_packet = mosq_test.gen_pubrel(mid=source_mid, proto_ver=proto_ver)
pubcomp_packet = mosq_test.gen_pubcomp(mid=source_mid, proto_ver=proto_ver)

mid = 1
publish_packet_r1 = mosq_test.gen_publish(topic, mid=mid, qos=qos, payload=payload, proto_ver=proto_ver)
publish_packet_r2 = mosq_test.gen_publish(topic, mid=mid, qos=qos, payload=payload, proto_ver=proto_ver, dup=1)

broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

try:
    # Connect and set up subscription, then disconnect
    sock = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=5, port=port)
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")
    sock.close()

    #persist_help.check_counts(port, clients=1, subscriptions=1)

    # Helper - send message then disconnect
    sock = mosq_test.do_client_connect(connect2_packet, connack2_packet, timeout=5, port=port)
    mosq_test.do_send_receive(sock, publish_packet, pubrec_packet, "pubrec")
    mosq_test.do_send_receive(sock, pubrel_packet, pubcomp_packet, "pubcomp")
    sock.close()

    #persist_help.check_counts(port, clients=1, client_msgs=1, base_msgs=1, subscriptions=1)

    # Reconnect, receive publish, disconnect
    sock = mosq_test.do_client_connect(connect1_packet, connack1_packet2, timeout=5, port=port)
    mosq_test.expect_packet(sock, "publish 1", publish_packet_r1)

    #persist_help.check_counts(port, clients=1, client_msgs=1, base_msgs=1, subscriptions=1)

    # Reconnect, receive publish, disconnect - dup should now be set
    sock = mosq_test.do_client_connect(connect1_packet, connack1_packet2, timeout=5, port=port)
    mosq_test.expect_packet(sock, "publish 2", publish_packet_r2)

    (broker_terminate_rc, stde) = mosq_test.terminate_broker(broker)
    broker = None

    persist_help.check_counts(port, clients=1, client_msgs_out=1, base_msgs=1, subscriptions=1)

    # Check client
    persist_help.check_client(port, client_id, None, 0, 0, port, 0, 2, 1, 4294967295, 0)

    # Check subscription
    persist_help.check_subscription(port, client_id, topic, qos, 0)

    # Check stored message
    store_id = persist_help.check_base_msg(port, 0, topic, payload_b, source_id, None, len(payload_b), source_mid, port, qos, 0)

    # Check client msg
    persist_help.check_client_msg(port, client_id, 1, store_id, 1, persist_help.dir_out, 1, qos, 0, persist_help.ms_wait_for_pubrec)

    rc = broker_terminate_rc
finally:
    if broker is not None:
        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated (2)")
            if rc == 0: rc=1
        (_, stde) = broker.communicate()
    os.remove(conf_file)
    rc += persist_help.cleanup(port)

    if rc:
        print(stde.decode('utf-8'))

exit(rc)
