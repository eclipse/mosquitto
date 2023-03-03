#!/usr/bin/env python3

# Test whether a client will is transmitted correctly, with per_listener_settings enabled

from mosq_test_helper import *

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("per_listener_settings true\n")
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")

def do_test(proto_ver, clean_session):
    rc = 1
    mid = 53
    connect1_packet = mosq_test.gen_connect("will-qos0-test", proto_ver=proto_ver)
    connack1_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    connect2_packet = mosq_test.gen_connect("test-helper", will_topic="will/qos0/test", will_payload=b"will-message", clean_session=clean_session, proto_ver=proto_ver, session_expiry=60)
    connack2_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    subscribe_packet = mosq_test.gen_subscribe(mid, "will/qos0/test", 0, proto_ver=proto_ver)
    suback_packet = mosq_test.gen_suback(mid, 0, proto_ver=proto_ver)

    publish_packet = mosq_test.gen_publish("will/qos0/test", qos=0, payload="will-message", proto_ver=proto_ver)

    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port)
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port, use_conf=True)

    try:
        sock = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=5, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        sock2 = mosq_test.do_client_connect(connect2_packet, connack2_packet, port=port, timeout=5)
        sock2.close()

        mosq_test.expect_packet(sock, "publish", publish_packet)
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

do_test(4, True)
do_test(4, False)
do_test(5, True)
do_test(5, False)
exit(0)
