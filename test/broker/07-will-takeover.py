#!/usr/bin/env python3

# Test whether a will is published when a client takes over an existing session that has a will set.
#
from mosq_test_helper import *


def do_test(proto_ver, clean_session1, clean_session2):
    rc = 1
    keepalive = 60

    mid = 1
    connect1_packet = mosq_test.gen_connect("will-helper", keepalive=keepalive, proto_ver=proto_ver)
    connack1_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    if proto_ver == 5:
        if clean_session1 == False:
            connect_props1 = mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_SESSION_EXPIRY_INTERVAL, 60)
        else:
            connect_props1 = mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_SESSION_EXPIRY_INTERVAL, 0)

        if clean_session2 == False:
            connect_props2 = mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_SESSION_EXPIRY_INTERVAL, 60)
        else:
            connect_props2 = mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_SESSION_EXPIRY_INTERVAL, 0)
    else:
        connect_props1 = b""
        connect_props2 = b""

    connect2_packet = mosq_test.gen_connect("will-test", keepalive=keepalive, proto_ver=proto_ver, will_topic="will/test", will_payload=b"LWT", clean_session=clean_session1, properties=connect_props1)
    connack2_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    connect3_packet = mosq_test.gen_connect("will-test", keepalive=keepalive, proto_ver=proto_ver, clean_session=clean_session2, properties=connect_props2)
    if clean_session1 == False and clean_session2 == False:
        connack3_packet = mosq_test.gen_connack(rc=0, flags=1, proto_ver=proto_ver)
    else:
        connack3_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    subscribe_packet = mosq_test.gen_subscribe(mid, "will/test", 0, proto_ver=proto_ver)
    suback_packet = mosq_test.gen_suback(mid, 0, proto_ver=proto_ver)

    publish_packet = mosq_test.gen_publish(topic="will/test", qos=0, payload="Client ready", proto_ver=proto_ver)
    publish_lwt_packet = mosq_test.gen_publish(topic="will/test", qos=0, payload="LWT", proto_ver=proto_ver)

    port = mosq_test.get_port()
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        # Connect helper to look for will being published
        sock1 = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=5, port=port)
        mosq_test.do_send_receive(sock1, subscribe_packet, suback_packet, "suback")

        # Connect client with will
        sock2 = mosq_test.do_client_connect(connect2_packet, connack2_packet, timeout=5, port=port)

        # Send a "ready" message
        sock2.send(publish_packet)
        mosq_test.expect_packet(sock1, "publish 1", publish_packet)

        # Connect client with will again as a separate connection, this should
        # take over from the previous one but only trigger a Will if we are taking
        # over a clean session/session-expiry-interval==0 client
        sock3 = mosq_test.do_client_connect(connect3_packet, connack3_packet, timeout=5, port=port)
        sock2.close()

        if clean_session1 == True or clean_session2 == True:
            mosq_test.expect_packet(sock1, "publish LWT", publish_lwt_packet)

        # Send the "ready" message again
        sock3.send(publish_packet)
        mosq_test.expect_packet(sock1, "publish 2", publish_packet)
        # If the helper has received a will message, then the ping test will fail
        mosq_test.do_ping(sock1)
        rc = 0

        sock1.close()
        sock2.close()
        sock3.close()
    except mosq_test.TestError:
        pass
    finally:
        broker.terminate()
        broker.wait()
        (stdo, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
            print("proto_ver=%d clean_session1=%d clean_session2=%d" % (proto_ver, clean_session1, clean_session2))
            exit(rc)


do_test(proto_ver=4, clean_session1=True, clean_session2=True)
do_test(proto_ver=4, clean_session1=False, clean_session2=True)
do_test(proto_ver=4, clean_session1=True, clean_session2=False)
do_test(proto_ver=4, clean_session1=False, clean_session2=False)
do_test(proto_ver=5, clean_session1=True, clean_session2=True)
do_test(proto_ver=5, clean_session1=False, clean_session2=True)
do_test(proto_ver=5, clean_session1=True, clean_session2=False)
do_test(proto_ver=5, clean_session1=False, clean_session2=False)
