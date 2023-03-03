#!/usr/bin/env python3

# A clean start=False client connects, and publishes to a topic it has access
# to with QoS 2 - but does not send a PUBREL. It closes the connection. The
# access to the topic is revoked, the client reconnects and it attempts to
# complete the flow. Is the publish allowed? It should not be.

from mosq_test_helper import *

def write_config(filename, port, plugin_ver):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("auth_plugin c/auth_plugin_acl_change.so\n")
        f.write("allow_anonymous true\n")

def do_test(plugin_ver):
    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port, plugin_ver)

    rc = 1
    connect1_packet = mosq_test.gen_connect("acl-change-test", clean_session=False)
    connack1_packet = mosq_test.gen_connack(rc=0)

    connect2_packet = mosq_test.gen_connect("acl-change-test", clean_session=False)
    connack2_packet = mosq_test.gen_connack(rc=0,flags=1)

    mid = 1
    subscribe_packet = mosq_test.gen_subscribe(mid, "#", 0)
    suback_packet = mosq_test.gen_suback(mid, 0)

    mid = 2
    publish1_packet = mosq_test.gen_publish("publish/topic", qos=2, mid=mid, payload="message")
    pubrec1_packet = mosq_test.gen_pubrec(mid)
    pubrel1_packet = mosq_test.gen_pubrel(mid)
    pubcomp1_packet = mosq_test.gen_pubcomp(mid)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    try:
        sock = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=20, port=port)

        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback 1")
        mosq_test.do_send_receive(sock, publish1_packet, pubrec1_packet, "pubrec")
        sock.close()

        # ACL has changed
        sock = mosq_test.do_client_connect(connect2_packet, connack2_packet, timeout=20, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback 2")
        mosq_test.do_send_receive(sock, pubrel1_packet, pubcomp1_packet, "pubcomp")
        mosq_test.do_ping(sock)

        rc = 0

        sock.close()
    except mosq_test.TestError:
        pass
    except Exception as err:
        print(err)
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

do_test(4)
