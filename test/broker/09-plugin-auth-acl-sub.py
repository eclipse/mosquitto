#!/usr/bin/env python3

# Test topic subscription. All topic are allowed but not using wildcard in subscribe.

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
    connect_packet = mosq_test.gen_connect("connect-uname-pwd-test", username="readonly")
    connack_packet = mosq_test.gen_connack(rc=0)

    mid = 53
    subscribe_packet = mosq_test.gen_subscribe(mid, "qos0/test", 0)
    suback_packet = mosq_test.gen_suback(mid, 0)

    mid_fail = 54
    subscribe_packet_fail = mosq_test.gen_subscribe(mid_fail, "#", 0)
    if plugin_ver == 2:
        suback_packet_fail = mosq_test.gen_suback(mid_fail, 0)
    else:
        suback_packet_fail = mosq_test.gen_suback(mid_fail, 0x80)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        mosq_test.do_send_receive(sock, subscribe_packet_fail, suback_packet_fail, "suback")

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
