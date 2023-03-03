#!/usr/bin/env python3

# Test whether a client subscribed to a topic receives its own message sent to that topic.

from mosq_test_helper import *

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")
        f.write("persistence true\n")
        f.write("persistence_file mosquitto-%d.db\n" % (port))

def do_test(proto_ver):
    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port)

    rc = 1
    mid = 530
    connect_packet = mosq_test.gen_connect(
        "persistent-subscription-test", clean_session=False, proto_ver=proto_ver, session_expiry=60
    )
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)
    connack_packet2 = mosq_test.gen_connack(rc=0, flags=1, proto_ver=proto_ver)  # session present

    subscribe_packet = mosq_test.gen_subscribe(mid, "subpub/qos1", 1, proto_ver=proto_ver)
    suback_packet = mosq_test.gen_suback(mid, 1, proto_ver=proto_ver)

    mid = 300
    publish_packet = mosq_test.gen_publish("subpub/qos1", qos=1, mid=mid, payload="message", proto_ver=proto_ver)
    puback_packet = mosq_test.gen_puback(mid, proto_ver=proto_ver)

    mid = 1
    publish_packet2 = mosq_test.gen_publish("subpub/qos1", qos=1, mid=mid, payload="message", proto_ver=proto_ver)

    if os.path.exists('mosquitto-%d.db' % (port)):
        os.unlink('mosquitto-%d.db' % (port))

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    (stdo1, stde1) = ("", "")
    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1
        (stdo1, stde1) = broker.communicate()
        sock.close()
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

        sock = mosq_test.do_client_connect(connect_packet, connack_packet2, timeout=20, port=port)

        sock.send(publish_packet)
        mosq_test.receive_unordered(sock, puback_packet, publish_packet2, "puback/publish2")
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
        if os.path.exists('mosquitto-%d.db' % (port)):
            os.unlink('mosquitto-%d.db' % (port))
        if rc:
            print(stde.decode('utf-8'))
            print("proto_ver=%d" % (proto_ver))
            exit(rc)


do_test(proto_ver=4)
do_test(proto_ver=5)
exit(0)

