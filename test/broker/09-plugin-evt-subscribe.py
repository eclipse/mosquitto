#!/usr/bin/env python3

from mosq_test_helper import *

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("plugin c/plugin_evt_subscribe.so\n")
        f.write("allow_anonymous true\n")


def do_test():
    rc = 1
    connect_packet = mosq_test.gen_connect("plugin-evt-subscribe", proto_ver=5)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    mid = 1
    subscribe_packet = mosq_test.gen_subscribe(mid, "subscribe-topic", 1, proto_ver=5)
    suback_packet = mosq_test.gen_suback(mid, 1, proto_ver=5)

    mid = 2
    publish_packet1 = mosq_test.gen_publish("new-topic", mid=mid, qos=1, payload="message1", proto_ver=5)
    puback_packet1 = mosq_test.gen_puback(mid, proto_ver=5)
    publish_packet2 = mosq_test.gen_publish("new-topic", qos=0, payload="message1", proto_ver=5)

    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port)
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port, use_conf=True)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)

        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")
        sock.send(publish_packet1)
        mosq_test.receive_unordered(sock, puback_packet1, publish_packet2, "puback / publish2")

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
            exit(rc)


do_test()
