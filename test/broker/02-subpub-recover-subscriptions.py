#!/usr/bin/env python3

# Check whether a durable client keeps its subscriptions on reconnecting.

from mosq_test_helper import *

def publish_helper(port):
    connect_packet = mosq_test.gen_connect("subpub-sub-helper")
    connack_packet = mosq_test.gen_connack(rc=0)
    publish1_packet = mosq_test.gen_publish("not-shared/sub", qos=0, payload="message1")
    publish2_packet = mosq_test.gen_publish("shared/sub", qos=0, payload="message2")
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)
    sock.send(publish1_packet)
    sock.send(publish2_packet)
    sock.close()


def do_test(proto_ver):
    rc = 1
    if proto_ver == 5:
        props = mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_SESSION_EXPIRY_INTERVAL, 60)
        connect_packet = mosq_test.gen_connect("subpub-sub-test", proto_ver=proto_ver, clean_session=False, properties=props)
    else:
        connect_packet = mosq_test.gen_connect("subpub-sub-test", proto_ver=proto_ver, clean_session=False)
    connack1_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)
    connack2_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver, flags=1)

    mid = 1
    subscribe1_packet = mosq_test.gen_subscribe(mid, "not-shared/sub", 0, proto_ver=proto_ver)
    suback1_packet = mosq_test.gen_suback(mid, 0, proto_ver=proto_ver)

    mid = 2
    subscribe2_packet = mosq_test.gen_subscribe(mid, "$share/name/shared/sub", 0, proto_ver=proto_ver)
    suback2_packet = mosq_test.gen_suback(mid, 0, proto_ver=proto_ver)

    publish1_packet = mosq_test.gen_publish("not-shared/sub", qos=0, payload="message1", proto_ver=proto_ver)
    publish2_packet = mosq_test.gen_publish("shared/sub", qos=0, payload="message2", proto_ver=proto_ver)

    port = mosq_test.get_port()
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack1_packet, timeout=2, port=port, connack_error="connack 1")

        mosq_test.do_send_receive(sock, subscribe1_packet, suback1_packet, "suback1")
        mosq_test.do_send_receive(sock, subscribe2_packet, suback2_packet, "suback2")

        publish_helper(port)
        mosq_test.expect_packet(sock, "publish1", publish1_packet)
        if proto_ver == 5:
            mosq_test.expect_packet(sock, "publish2", publish2_packet)
        sock.close()

        # Reconnect, but don't resubscribe
        sock = mosq_test.do_client_connect(connect_packet, connack2_packet, timeout=2, port=port, connack_error="connack 2")

        publish_helper(port)
        mosq_test.expect_packet(sock, "publish1", publish1_packet)
        if proto_ver == 5:
            mosq_test.expect_packet(sock, "publish2", publish2_packet)
        sock.close()

        rc = 0

        sock.close()
    except mosq_test.TestError:
        pass
    except Exception as err:
        print(err)
    finally:
        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1
        (stdo, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
            exit(rc)


do_test(proto_ver=4)
do_test(proto_ver=5)
exit(0)
