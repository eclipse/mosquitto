#!/usr/bin/env python3

# Bug specific test - if a QoS2 publish is denied, then we publish again with
# the same mid to a topic that is allowed, does it work properly?

from mosq_test_helper import *

def write_config(filename, port, plugin_ver):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("auth_plugin c/auth_plugin_v%d.so\n" % (plugin_ver))
        f.write("allow_anonymous false\n")

def do_test(plugin_ver):
    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port, plugin_ver)

    rc = 1
    connect1_packet = mosq_test.gen_connect("connect-uname-pwd-test", username="readwrite", clean_session=False)
    connack1_packet = mosq_test.gen_connack(rc=0)

    connect2_packet = mosq_test.gen_connect("connect-uname-pwd-test", username="readwrite", clean_session=False)
    connack2_packet = mosq_test.gen_connack(rc=0,flags=1)

    mid = 1
    subscribe_packet = mosq_test.gen_subscribe(mid, "readonly", 2)
    suback_packet = mosq_test.gen_suback(mid, 2)

    mid = 2
    publish1_packet = mosq_test.gen_publish("readonly", qos=2, mid=mid, payload="message")
    pubrec1_packet = mosq_test.gen_pubrec(mid)
    pubrel1_packet = mosq_test.gen_pubrel(mid)
    pubcomp1_packet = mosq_test.gen_pubcomp(mid)

    mid = 2
    publish2_packet = mosq_test.gen_publish("writeable", qos=1, mid=mid, payload="message")
    puback2_packet = mosq_test.gen_puback(mid)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    try:
        sock = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=20, port=port)

        mosq_test.do_send_receive(sock, publish1_packet, pubrec1_packet, "pubrec1")
        sock.close()

        sock = mosq_test.do_client_connect(connect2_packet, connack2_packet, timeout=20, port=port)
        mosq_test.do_send_receive(sock, publish2_packet, puback2_packet, "puback2")

        mosq_test.do_ping(sock)

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

do_test(2)
do_test(3)
do_test(4)
do_test(5)
