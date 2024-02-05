#!/usr/bin/env python3

# Connect a client, add a subscription, disconnect, send a message with a
# different client, restore, reconnect, check it is received.

from mosq_test_helper import *
persist_help = persist_module()

port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
persist_help.write_config(conf_file, port)

rc = 1

persist_help.init(port)

client_id = "persist-cmsg-v3-1-1"
payload = "queued message 1"
payload_b = payload.encode("UTF-8")
qos = 1
topic = "client-msg/test"
source_id = "persist-cmsg-v3-1-1-helper"
proto_ver = 4

connect_packet = mosq_test.gen_connect(client_id, proto_ver=proto_ver, clean_session=False)
connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

mid = 1
subscribe_packet = mosq_test.gen_subscribe(mid, topic, qos, proto_ver=proto_ver)
suback_packet = mosq_test.gen_suback(mid, qos=qos, proto_ver=proto_ver)

connect2_packet = mosq_test.gen_connect(source_id, proto_ver=proto_ver)
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

    (broker_terminate_rc, stde) = mosq_test.terminate_broker(broker)
    broker = None

    persist_help.check_counts(port, clients=1, client_msgs_out=1, base_msgs=1, subscriptions=1)

    # Check client
    persist_help.check_client(port, client_id, None, 0, 0, port, 0, 2, 1, 4294967295, 0)

    # Check subscription
    persist_help.check_subscription(port, client_id, topic, qos, 0)

    # Check stored message
    store_id = persist_help.check_base_msg(port, 0, topic, payload_b, source_id, None, len(payload_b), mid, port, qos, 0)

    # Check client msg
    persist_help.check_client_msg(port, client_id, 1, store_id, 0, persist_help.dir_out, 1, qos, 0, persist_help.ms_queued)

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
