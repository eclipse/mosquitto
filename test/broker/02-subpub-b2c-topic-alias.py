#!/usr/bin/env python3

# Test whether "topic alias" works from the broker
# MQTT v5

from mosq_test_helper import *

def do_test(start_broker):
    rc = 1
    props = mqtt5_props.gen_uint16_prop(mqtt5_props.PROP_TOPIC_ALIAS_MAXIMUM, 65535)
    connect_packet = mosq_test.gen_connect("02-b2c-topic-alias", proto_ver=5, properties=props)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    subscribe_packet = mosq_test.gen_subscribe(topic="02/b2c/topic/alias/#", qos=0, mid=1, proto_ver=5)
    suback_packet = mosq_test.gen_suback(qos=0, mid=1, proto_ver=5)

    connect_packet_helper = mosq_test.gen_connect("02-b2c-topic-alias-helper", proto_ver=5)
    connack_packet_helper = mosq_test.gen_connack(rc=0, proto_ver=5)

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port, nolog=True)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port)
        helper = mosq_test.do_client_connect(connect_packet_helper, connack_packet_helper, timeout=5, port=port)

        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet)

        # This test allows us to test up to the 65535 aliases, but the default
        # max_topic_alias_broker setting is 10, so use that.
        max_alias = 10

        # Send messages so the broker configures topic aliases
        publish_packet_s = b""
        publish_packet_r = b""
        for i in range(1, max_alias):
            # This doesn't make sense in the max_alias=10 case, but for higher values it speeds up the test
            if i % 50 == 0:
                sock.send(publish_packet_s)
                mosq_test.expect_packet(sock, "publish %da"%(i), publish_packet_r)
                publish_packet_s = b""
                publish_packet_r = b""

            publish_packet_s += mosq_test.gen_publish("02/b2c/topic/alias/%d"%(i), qos=0, payload="message", proto_ver=5)

            props = mqtt5_props.gen_uint16_prop(mqtt5_props.PROP_TOPIC_ALIAS, i)
            publish_packet_r += mosq_test.gen_publish("02/b2c/topic/alias/%d"%(i), qos=0, payload="message", proto_ver=5, properties=props)

        if len(publish_packet_s) > 0:
            sock.send(publish_packet_s)
            mosq_test.expect_packet(sock, "publish %da"%(i), publish_packet_r)

        # Re-send now aliases have been configured by the broker
        publish_packet_s = b""
        publish_packet_r = b""
        for i in range(1, max_alias):
            if i % 50 == 0:
                sock.send(publish_packet_s)
                mosq_test.expect_packet(sock, "publish %db"%(i), publish_packet_r)
                publish_packet_s = b""
                publish_packet_r = b""

            publish_packet_s += mosq_test.gen_publish("02/b2c/topic/alias/%d"%(i), qos=0, payload="message", proto_ver=5)

            props = mqtt5_props.gen_uint16_prop(mqtt5_props.PROP_TOPIC_ALIAS, i)
            publish_packet_r += mosq_test.gen_publish("", qos=0, payload="message", proto_ver=5, properties=props)

        if len(publish_packet_s) > 0:
            sock.send(publish_packet_s)
            mosq_test.expect_packet(sock, "publish %db"%(i), publish_packet_r)

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


def all_tests(start_broker=False):
    rc = do_test(start_broker)
    if rc:
        return rc;
    return 0

if __name__ == '__main__':
    all_tests(True)
