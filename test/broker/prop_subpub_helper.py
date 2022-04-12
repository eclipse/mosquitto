#!/usr/bin/env python3

# Test whether a client subscribed to a topic receives its own message sent to that topic.
# Does a given property get sent through?
# MQTT v5

from mosq_test_helper import *

def prop_subpub_helper(start_broker, test_name, props_out, props_in, expect_proto_error=False):
    rc = 1
    mid = 53
    connect_packet = mosq_test.gen_connect(test_name, proto_ver=5)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    subscribe_packet = mosq_test.gen_subscribe(mid, "%s/subpub/qos0" % (test_name), 0, proto_ver=5)
    suback_packet = mosq_test.gen_suback(mid, 0, proto_ver=5)

    publish_packet_out = mosq_test.gen_publish("%s/subpub/qos0" % (test_name), qos=0, payload="message", proto_ver=5, properties=props_out)

    publish_packet_expected = mosq_test.gen_publish("%s/subpub/qos0" % (test_name), qos=0, payload="message", proto_ver=5, properties=props_in)

    disconnect_packet = mosq_test.gen_disconnect(reason_code=mqtt5_rc.MQTT_RC_PROTOCOL_ERROR, proto_ver=5)

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)

        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")
        if expect_proto_error:
            mosq_test.do_send_receive(sock, publish_packet_out, disconnect_packet, "publish")
        else:
            mosq_test.do_send_receive(sock, publish_packet_out, publish_packet_expected, "publish")

        rc = 0

        sock.close()
    except mosq_test.TestError:
        pass
    finally:
        if start_broker:
            broker.terminate()
            if mosq_test.wait_for_subprocess(broker):
                print("broker not terminated")
                if rc == 0: rc=1
            (stdo, stde) = broker.communicate()
            if rc:
                print(stde.decode('utf-8'))
                exit(rc)
        else:
            return rc
