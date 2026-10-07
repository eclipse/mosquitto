#!/usr/bin/env python3

# Connect a client, add a subscription, disconnect, send a message with a
# different client, restore, reconnect, check it is received.

from mosq_test_helper import *
persist_help = persist_module()

port, _ = mosq_test.get_port(2)
conf_file = os.path.basename(__file__).replace('.py', '.conf')
persist_help.write_config(conf_file, port)

rc = 1

persist_help.init(port)

keepalive = 10
client_id = "persist-client-msg-v3-1-1"
proto_ver = 4

helper_id = "persist-client-msg-v3-1-1-helper"
topic0 = "client-msg/0"
topic1 = "client-msg/1"
topic2 = "client-msg/2"

connect_packet = mqtt_packets.gen_connect(client_id, keepalive=keepalive, proto_ver=proto_ver, clean_session=False)
connack_packet1 = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)
connack_packet2 = mqtt_packets.gen_connack(rc=0, flags=1, proto_ver=proto_ver)
mid = 1
subscribe_packet0 = mqtt_packets.gen_subscribe(mid, topic0, qos=0, proto_ver=proto_ver)
suback_packet0 = mqtt_packets.gen_suback(mid=mid, qos=0, proto_ver=proto_ver)
subscribe_packet1 = mqtt_packets.gen_subscribe(mid, topic1, qos=1, proto_ver=proto_ver)
suback_packet1 = mqtt_packets.gen_suback(mid=mid, qos=1, proto_ver=proto_ver)
subscribe_packet2 = mqtt_packets.gen_subscribe(mid, topic2, qos=2, proto_ver=proto_ver)
suback_packet2 = mqtt_packets.gen_suback(mid=mid, qos=2, proto_ver=proto_ver)

connect_packet_helper = mqtt_packets.gen_connect(helper_id, keepalive=keepalive, proto_ver=proto_ver, clean_session=True)
publish_packet0 = mqtt_packets.gen_publish(topic=topic0, qos=0, payload="message", proto_ver=proto_ver)
mid = 1
publish_packet1 = mqtt_packets.gen_publish(topic=topic1, qos=1, payload="message", mid=mid, proto_ver=proto_ver)
puback_packet = mqtt_packets.gen_puback(mid=mid, proto_ver=proto_ver)
mid = 2
publish_packet2 = mqtt_packets.gen_publish(topic=topic2, qos=2, payload="message", mid=mid, proto_ver=proto_ver)
pubrec_packet = mqtt_packets.gen_pubrec(mid=mid, proto_ver=proto_ver)
pubrel_packet = mqtt_packets.gen_pubrel(mid=mid, proto_ver=proto_ver)
pubcomp_packet = mqtt_packets.gen_pubcomp(mid=mid, proto_ver=proto_ver)


broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

con = None
try:
    # Connect client, subscribe, disconnect
    sock = mosq_test.do_client_connect(connect_packet, connack_packet1, timeout=5, port=port)
    mosq_test.do_send_receive(sock, subscribe_packet0, suback_packet0, "suback 0")
    mosq_test.do_send_receive(sock, subscribe_packet1, suback_packet1, "suback 1")
    mosq_test.do_send_receive(sock, subscribe_packet2, suback_packet2, "suback 2")
    sock.close()

    # Connect helper and publish
    helper = mosq_test.do_client_connect(connect_packet_helper, connack_packet1, timeout=5, port=port)
    helper.send(publish_packet0)
    mosq_test.do_send_receive(helper, publish_packet1, puback_packet, "puback helper")
    mosq_test.do_send_receive(helper, publish_packet2, pubrec_packet, "pubrec helper")
    mosq_test.do_send_receive(helper, pubrel_packet, pubcomp_packet, "pubcomp helper")
    helper.close()

    # Kill broker
    (broker_terminate_rc, stde) = mosq_test.terminate_broker(broker)
    broker = None

    persist_help.check_counts(port, clients=1, client_msgs_out=2, base_msgs=2, subscriptions=3)

    # Restart broker
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    # Connect client again, it should have a session
    sock = mosq_test.do_client_connect(connect_packet, connack_packet2, timeout=5, port=port)

    # Does the client get the messages
    mosq_test.do_receive_send(sock, publish_packet1, puback_packet, "publish 1")
    mosq_test.do_receive_send(sock, publish_packet2, pubrec_packet, "publish 2")
    mosq_test.do_receive_send(sock, pubrel_packet, pubcomp_packet, "pubrel 2")
    # Send ping and wait for the PINGRESP to make sure the broker has processed all sent pubcomp
    mosq_test.do_ping(sock)
    sock.close()

    # Connect client again, it should have a session
    sock = mosq_test.do_client_connect(connect_packet, connack_packet2, timeout=5, port=port)
    # If there are messages, the ping will fail
    mosq_test.do_ping(sock)

    (broker_terminate_rc, stde) = mosq_test.terminate_broker(broker)
    broker = None

    persist_help.check_counts(port, clients=1, subscriptions=3)

    rc = broker_terminate_rc
finally:
    if broker is not None:
        mosq_test.terminate_broker(broker)
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1
    os.remove(conf_file)
    rc += persist_help.cleanup(port)

    if rc:
        print(mosq_test.broker_log(broker))


exit(rc)
