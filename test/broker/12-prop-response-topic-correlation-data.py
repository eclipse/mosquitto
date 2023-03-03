#!/usr/bin/env python3

# client 1 subscribes to normal-topic
# client 2 susbscribes to response-topic
# client 2 publishes message to normal-topic with response-topic property and correlation-data property
# client 1 receives message, publishes a response on response-topic
# client 2 receives message, checks payload

from mosq_test_helper import *

def do_test(start_broker):
    rc = 1

    connect_packet1 = mosq_test.gen_connect("client1", proto_ver=5)
    connect_packet2 = mosq_test.gen_connect("client2", proto_ver=5)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    subscribe_packet1 = mosq_test.gen_subscribe(mid=1, topic="normal/topic", qos=0, proto_ver=5)
    subscribe_packet2 = mosq_test.gen_subscribe(mid=1, topic="response/topic", qos=0, proto_ver=5)
    suback_packet = mosq_test.gen_suback(mid=1, qos=0, proto_ver=5)

    props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_RESPONSE_TOPIC, "response/topic")
    props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_CORRELATION_DATA, "45vyvynq30q3vt4 nuy893b4v3")
    publish_packet2 = mosq_test.gen_publish(topic="normal/topic", qos=0, payload="2", proto_ver=5, properties=props)

    publish_packet1 = mosq_test.gen_publish(topic="response/topic", qos=0, payload="22", proto_ver=5)

    disconnect_client_packet = mosq_test.gen_disconnect(proto_ver=5, properties=props)

    disconnect_server_packet = mosq_test.gen_disconnect(proto_ver=5, reason_code=130)

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock1 = mosq_test.do_client_connect(connect_packet1, connack_packet, port=port)
        sock2 = mosq_test.do_client_connect(connect_packet2, connack_packet, port=port)

        mosq_test.do_send_receive(sock1, subscribe_packet1, suback_packet, "subscribe1")
        mosq_test.do_send_receive(sock2, subscribe_packet2, suback_packet, "subscribe2")

        sock2.send(publish_packet2)
        mosq_test.expect_packet(sock1, "publish1", publish_packet2)
        # FIXME - it would be better to extract the property and payload, even though we know them
        sock1.send(publish_packet1)
        mosq_test.expect_packet(sock2, "publish2", publish_packet1)
        rc = 0

        sock1.close()
        sock2.close()
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
