#!/usr/bin/env python3

# Test whether a client will that is too large is handled

from mosq_test_helper import *

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")
        f.write("message_size_limit 1\n")

def do_test(proto_ver, clean_session):
    rc = 1
    mid = 53
    connect_packet = mosq_test.gen_connect("will-test", proto_ver=proto_ver)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    connect_packet_ok = mosq_test.gen_connect("test-helper", will_topic="will/qos0/test", will_payload=b"A", clean_session=clean_session, proto_ver=proto_ver, session_expiry=60)
    connack_packet_ok = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    connect_packet_bad = mosq_test.gen_connect("test-helper", will_topic="will/qos0/test", will_payload=b"AB", clean_session=clean_session, proto_ver=proto_ver, session_expiry=60)
    if proto_ver == 5:
        connack_packet_bad = mosq_test.gen_connack(rc=mqtt5_rc.MQTT_RC_PACKET_TOO_LARGE, proto_ver=proto_ver, property_helper=False)
    else:
        connack_packet_bad = mosq_test.gen_connack(rc=5, proto_ver=proto_ver)

    subscribe_packet = mosq_test.gen_subscribe(mid, "will/qos0/test", 0, proto_ver=proto_ver)
    suback_packet = mosq_test.gen_suback(mid, 0, proto_ver=proto_ver)

    publish_packet = mosq_test.gen_publish("will/qos0/test", qos=0, payload="A", proto_ver=proto_ver)

    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        sock2 = mosq_test.do_client_connect(connect_packet_bad, connack_packet_bad, port=port, timeout=5)
        sock2.close()

        sock2 = mosq_test.do_client_connect(connect_packet_ok, connack_packet_ok, port=port, timeout=5)
        sock2.close()

        mosq_test.expect_packet(sock, "publish", publish_packet)
        # Check there are no more messages
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

do_test(4, True)
do_test(4, False)
do_test(5, True)
do_test(5, False)
exit(0)
