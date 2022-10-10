#!/usr/bin/env python3

from mosq_test_helper import *

def write_config(filename, port1, port2):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port1))
        f.write("allow_anonymous true\n")
        f.write("\n")
        f.write("listener %d\n" % (port2))
        f.write("allow_anonymous true\n")
        f.write("mount_point mount/\n")
        f.write("\n")
        f.write("log_type debug\n")


def helper(port, proto_ver):
    connect_packet = mosq_test.gen_connect("10-listener-mount-helper", proto_ver=proto_ver)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    publish_packet = mosq_test.gen_publish("10/listener/mount/test", qos=0, payload="mount point", proto_ver=proto_ver)

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port, connack_error="helper connack")
    sock.send(publish_packet)
    sock.close()


def do_test(proto_ver):
    (port1, port2) = mosq_test.get_port(2)
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port1, port2)

    rc = 1
    mid = 1

    # Subscriber for listener with mount point
    connect_packet1 = mosq_test.gen_connect("test1", proto_ver=proto_ver)
    connack_packet1 = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)
    subscribe_packet1 = mosq_test.gen_subscribe(mid, "#", 0, proto_ver=proto_ver)
    suback_packet1 = mosq_test.gen_suback(mid, 0, proto_ver=proto_ver)
    publish_packet1 = mosq_test.gen_publish("mount/10/listener/mount/test", qos=0, payload="mount point", proto_ver=proto_ver)

    # Subscriber for listener without mount point
    connect_packet2 = mosq_test.gen_connect("test2", proto_ver=proto_ver)
    connack_packet2 = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)
    subscribe_packet2 = mosq_test.gen_subscribe(mid, "#", 0, proto_ver=proto_ver)
    suback_packet2 = mosq_test.gen_suback(mid, 0, proto_ver=proto_ver)
    publish_packet2 = mosq_test.gen_publish("10/listener/mount/test", qos=0, payload="mount point", proto_ver=proto_ver)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port1)

    try:
        sock1 = mosq_test.do_client_connect(connect_packet1, connack_packet1, timeout=20, port=port1)
        mosq_test.do_send_receive(sock1, subscribe_packet1, suback_packet1, "suback1")

        sock2 = mosq_test.do_client_connect(connect_packet2, connack_packet2, timeout=20, port=port2)
        mosq_test.do_send_receive(sock2, subscribe_packet2, suback_packet2, "suback2")

        helper(port2, proto_ver)
        # Should have now received a publish command

        mosq_test.expect_packet(sock1, "publish1", publish_packet1)
        mosq_test.expect_packet(sock2, "publish2", publish_packet2)
        rc = 0

        sock1.close()
        sock2.close()
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
