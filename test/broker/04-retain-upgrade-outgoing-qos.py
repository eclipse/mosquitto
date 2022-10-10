#!/usr/bin/env python3

# Test whether a retained PUBLISH to a topic with QoS 0 is sent with subscriber QoS
# when upgrade_outgoing_qos is true

from mosq_test_helper import *

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")
        f.write("upgrade_outgoing_qos true\n")


def do_test(proto_ver):
    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port)

    rc = 1
    mid = 16
    connect_packet = mosq_test.gen_connect("retain-qos0-test", proto_ver=proto_ver)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    publish_packet = mosq_test.gen_publish("retain/qos0/test", qos=0, payload="retained message", retain=True, proto_ver=proto_ver)
    subscribe_packet = mosq_test.gen_subscribe(mid, "retain/qos0/test", 1, proto_ver=proto_ver)
    suback_packet = mosq_test.gen_suback(mid, 1, proto_ver=proto_ver)

    publish_packet2 = mosq_test.gen_publish("retain/qos0/test", mid=1, qos=1, payload="retained message", retain=True, proto_ver=proto_ver)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        sock.send(publish_packet)

        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        mosq_test.expect_packet(sock, "publish", publish_packet2)
        rc = 0

        sock.close()
    except mosq_test.TestError:
        pass
    finally:
        os.remove(conf_file)
        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1
        (stdo, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
            print("proto_ver=%d" % (proto_ver))
            exit(rc)

do_test(proto_ver=4)
do_test(proto_ver=5)
exit(0)
