#!/usr/bin/env python3

# Connect a client, start a QoS 2 flow, disconnect, restore, carry on with the
# QoS 2 flow. Is it received?

from mosq_test_helper import *
persist_help = persist_module()

port = mosq_test.get_port()
persist_help.init(port)
conf_file = os.path.basename(__file__).replace('.py', '.conf')
persist_help.write_config(conf_file, port)

rc = 1


client_id = "persist-client-msg-in-v3-1-1"
proto_ver = 4

helper_id = "persist-client-msg-in-v3-1-1-helper"
topic = "client-msg-in/2"
qos = 2
stde = b""

connect_packet = mosq_test.gen_connect(client_id, proto_ver=proto_ver, clean_session=False)
connack_packet1 = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)
connack_packet2 = mosq_test.gen_connack(rc=0, flags=1, proto_ver=proto_ver)

mid = 1
publish1_packet = mosq_test.gen_publish(topic=topic, qos=qos, payload="message1", mid=mid, proto_ver=proto_ver)
pubrec1_packet = mosq_test.gen_pubrec(mid=mid, proto_ver=proto_ver)
pubrel1_packet = mosq_test.gen_pubrel(mid=mid, proto_ver=proto_ver)
pubcomp1_packet = mosq_test.gen_pubcomp(mid=mid, proto_ver=proto_ver)

mid = 2
publish2_packet = mosq_test.gen_publish(topic=topic, qos=qos, payload="message2", mid=mid, proto_ver=proto_ver)
pubrec2_packet = mosq_test.gen_pubrec(mid=mid, proto_ver=proto_ver)
pubrel2_packet = mosq_test.gen_pubrel(mid=mid, proto_ver=proto_ver)
pubcomp2_packet = mosq_test.gen_pubcomp(mid=mid, proto_ver=proto_ver)

connect_packet_helper = mosq_test.gen_connect(helper_id, proto_ver=proto_ver, clean_session=True)
subscribe_packet = mosq_test.gen_subscribe(mid, topic, qos=qos, proto_ver=proto_ver)
suback_packet = mosq_test.gen_suback(mid=mid, qos=qos, proto_ver=proto_ver)

broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

con = None
try:
    # Connect client, start flow, disconnect
    sock = mosq_test.do_client_connect(connect_packet, connack_packet1, timeout=5, port=port, connack_error="connack 1")
    mosq_test.do_send_receive(sock, publish1_packet, pubrec1_packet, "pubrec1 send")
    mosq_test.do_send_receive(sock, publish2_packet, pubrec2_packet, "pubrec2 send")
    sock.close()

    # Kill broker
    (broker_terminate_rc, stde) = mosq_test.terminate_broker(broker)
    broker = None

    persist_help.check_counts(port, clients=1, client_msgs_in=2, base_msgs=2)

    # Restart broker
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    # Connect helper and subscribe
    helper = mosq_test.do_client_connect(connect_packet_helper, connack_packet1, timeout=5, port=port, connack_error="helper connack")
    mosq_test.do_send_receive(helper, subscribe_packet, suback_packet, "suback helper")

    # Complete the flow
    sock = mosq_test.do_client_connect(connect_packet, connack_packet2, timeout=5, port=port, connack_error="connack 2")
    mosq_test.do_send_receive(sock, pubrel1_packet, pubcomp1_packet, "pubrel1 send")
    mosq_test.do_send_receive(sock, pubrel2_packet, pubcomp2_packet, "pubrel2 send")

    mosq_test.expect_packet(helper, "publish1 receive", publish1_packet)
    mosq_test.expect_packet(helper, "publish2 receive", publish2_packet)
    helper.send(pubrec1_packet)
    mosq_test.do_receive_send(helper, pubrel1_packet, pubcomp1_packet, "pubcomp1 receive")

    helper.send(pubrec2_packet)
    mosq_test.do_receive_send(helper, pubrel2_packet, pubcomp2_packet, "pubcomp2 receive")

    # Send ping and wait for the PINGRESP to make sure the broker has processed all sent puback
    mosq_test.do_ping(helper)

    # Kill broker
    (broker_terminate_rc, stde) = mosq_test.terminate_broker(broker)
    broker = None

    persist_help.check_counts(port, clients=1)

    rc = broker_terminate_rc
finally:
    if broker is not None:
        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1
        (_, stde) = broker.communicate()
    os.remove(conf_file)
    rc += persist_help.cleanup(port)

    if rc:
        print(stde.decode('utf-8'))


exit(rc)
