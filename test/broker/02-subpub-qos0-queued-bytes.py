#!/usr/bin/env python3

from mosq_test_helper import *

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")
        f.write("max_inflight_messages 20\n")
        f.write("max_inflight_bytes 1000000\n")
        f.write("max_queued_messages 20\n")
        f.write("max_queued_bytes 1000000\n")

def do_test(proto_ver):
    rc = 1
    connect_packet = mosq_test.gen_connect("subpub-qos0-bytes", proto_ver=proto_ver)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    connect_packet_helper = mosq_test.gen_connect("qos0-bytes-helper", proto_ver=proto_ver)

    mid = 1
    subscribe_packet = mosq_test.gen_subscribe(mid, "subpub/qos0/queued/bytes", 1, proto_ver=proto_ver)
    suback_packet = mosq_test.gen_suback(mid, 1, proto_ver=proto_ver)

    publish_packet0 = mosq_test.gen_publish("subpub/qos0/queued/bytes", qos=0, payload="message", proto_ver=proto_ver)


    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port)
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=4, port=port, connack_error="connack 1")

        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        helper = mosq_test.do_client_connect(connect_packet_helper, connack_packet, timeout=4, port=port, connack_error="connack helper")

        helper.send(publish_packet0)
        mosq_test.expect_packet(sock, "publish0", publish_packet0)
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
