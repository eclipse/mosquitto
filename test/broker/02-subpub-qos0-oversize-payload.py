#!/usr/bin/env python3

# Test whether message size limits apply.

from mosq_test_helper import *

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")
        f.write("message_size_limit 1\n")

def do_test(proto_ver):
    rc = 1
    mid = 53
    connect_packet = mosq_test.gen_connect("02-subpub-qos0-oversize", proto_ver=proto_ver)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    subscribe_packet = mosq_test.gen_subscribe(mid, "subpub/qos0/oversize", 0, proto_ver=proto_ver)
    suback_packet = mosq_test.gen_suback(mid, 0, proto_ver=proto_ver)

    connect2_packet = mosq_test.gen_connect("02-subpub-qos0-oversize-helper", proto_ver=proto_ver)
    connack2_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    publish_packet_ok = mosq_test.gen_publish("subpub/qos0/oversize", qos=0, payload="A", proto_ver=proto_ver)
    publish_packet_bad = mosq_test.gen_publish("subpub/qos0/oversize", qos=0, payload="AB", proto_ver=proto_ver)

    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        sock2 = mosq_test.do_client_connect(connect2_packet, connack2_packet, timeout=20, port=port)
        sock2.send(publish_packet_ok)
        mosq_test.expect_packet(sock, "publish 1", publish_packet_ok)

        # Check all is still well on the publishing client
        mosq_test.do_ping(sock2)

        sock2.send(publish_packet_bad)

        # Check all is still well on the publishing client
        mosq_test.do_ping(sock2)

        # The subscribing client shouldn't have received a PUBLISH
        mosq_test.do_ping(sock)
        rc = 0

        sock.close()
    except SyntaxError:
        raise
    except TypeError:
        raise
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
