#!/usr/bin/env python3

# Test whether a PUBLISH to $ topics QoS 1 results in the expected PUBACK packet.

from mosq_test_helper import *

mid = 1
def helper(port, topic, reason_code):
    global mid

    connect_packet = mosq_test.gen_connect("03-publish-dollar-v5", proto_ver=5)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)
    publish_packet = mosq_test.gen_publish(topic, qos=1, mid=mid, payload="message", proto_ver=5)

    if reason_code == 0:
        puback_packet = mosq_test.gen_puback(mid, proto_ver=5)
    else:
        puback_packet = mosq_test.gen_puback(mid, proto_ver=5, reason_code=reason_code)

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
    mosq_test.do_send_receive(sock, publish_packet, puback_packet, "puback%d"%(mid))
    mid += 1


def do_test(start_broker):
    rc = 1

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        helper(port, "$SYS/broker/uptime", mqtt5_rc.MQTT_RC_NOT_AUTHORIZED)
        helper(port, "$SYS/broker/connection/me", mqtt5_rc.MQTT_RC_NOT_AUTHORIZED)
        helper(port, "$SYS/broker/connection/me/state", mqtt5_rc.MQTT_RC_NO_MATCHING_SUBSCRIBERS)
        helper(port, "$share/share/03/publish/dollar/v5/topic", mqtt5_rc.MQTT_RC_NOT_AUTHORIZED)

        rc = 0
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


def all_tests(start_broker=False):
    return do_test(start_broker)

if __name__ == '__main__':
    all_tests(True)
