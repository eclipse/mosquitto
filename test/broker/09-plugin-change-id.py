#!/usr/bin/env python3

from mosq_test_helper import *

def write_config(filename, port, plugin_ver):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("auth_plugin c/auth_plugin_id_change.so\n")
        f.write("allow_anonymous true\n")

def do_test(plugin_ver):
    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port, plugin_ver)

    rc = 1
    connect1_packet = mosq_test.gen_connect("already-exists")
    connack1_packet = mosq_test.gen_connack(rc=0)

    connect2_packet = mosq_test.gen_connect("id-change-test")
    connack2_packet = mosq_test.gen_connack(rc=0)

    mid = 1
    subscribe_packet = mosq_test.gen_subscribe(mid, "#", 0)
    # Only subs by client id == allowed is allowed
    suback_packet_denied = mosq_test.gen_suback(mid, 128)
    suback_packet_ok = mosq_test.gen_suback(mid, 0)

    mid = 2
    publish1_packet = mosq_test.gen_publish("publish/topic", qos=2, mid=mid, payload="message")
    pubrec1_packet = mosq_test.gen_pubrec(mid)
    pubrel1_packet = mosq_test.gen_pubrel(mid)
    pubcomp1_packet = mosq_test.gen_pubcomp(mid)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    try:
        sock1 = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=20, port=port)
        sock2 = mosq_test.do_client_connect(connect2_packet, connack2_packet, timeout=20, port=port)

        mosq_test.do_send_receive(sock1, subscribe_packet, suback_packet_denied, "suback denied")
        mosq_test.do_send_receive(sock2, subscribe_packet, suback_packet_ok, "suback ok")

        mosq_test.do_ping(sock1)
        mosq_test.do_ping(sock2)
        sock1.close()
        sock2.close()

        rc = 0
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
