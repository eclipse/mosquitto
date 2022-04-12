#!/usr/bin/env python3

# What does the broker do if an MQTT v5 client doesn't respect max_inflight_messages?

from mosq_test_helper import *

def do_test(proto_ver):
    port = mosq_test.get_port()

    rc = 1
    connect_packet = mosq_test.gen_connect("pub-qos2-inflight-exceeded", proto_ver=proto_ver)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port, timeout=10)

        for i in range(1, 21):
            publish_packet = mosq_test.gen_publish("pub/qos2/max/inflight/exceeded", qos=2, mid=i, payload="message", proto_ver=proto_ver)
            pubrec_packet = mosq_test.gen_pubrec(mid=i, proto_ver=proto_ver)
            mosq_test.do_send_receive(sock, publish_packet, pubrec_packet)

        i = 21
        publish_packet = mosq_test.gen_publish("pub/qos2/max/inflight/exceeded", qos=2, mid=i, payload="message", proto_ver=proto_ver)
        if proto_ver == 5:
            disconnect_packet = mosq_test.gen_disconnect(reason_code=mqtt5_rc.MQTT_RC_RECEIVE_MAXIMUM_EXCEEDED, proto_ver=proto_ver)
        else:
            disconnect_packet = b""
        mosq_test.do_send_receive(sock, publish_packet, disconnect_packet, "disconnect")

        rc = 0

        sock.close()
    except mosq_test.TestError:
        pass
    finally:
        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1
        (stdo, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
            print("proto_ver=%d" % (proto_ver))
            exit(rc)


do_test(proto_ver=4)
do_test(proto_ver=5)
exit(0)
