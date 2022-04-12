#!/usr/bin/env python3

# MQTT v5 session takeover test

from mosq_test_helper import *

port = mosq_test.get_port()
broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

try:
    rc = 1
    connect_packet = mosq_test.gen_connect("take-over", proto_ver=5)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)
    disconnect_packet = mosq_test.gen_disconnect(reason_code=mqtt5_rc.MQTT_RC_SESSION_TAKEN_OVER, proto_ver=5)

    sock1 = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
    sock2 = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
    mosq_test.expect_packet(sock1, "disconnect", disconnect_packet)
    mosq_test.do_ping(sock2)

    sock2.close()
    sock1.close()
    rc = 0
except mosq_test.TestError:
    pass
except Exception as e:
    print(e)
finally:
    broker.terminate()
    if mosq_test.wait_for_subprocess(broker):
        print("broker not terminated")
        if rc == 0: rc=1
    (stdo, stde) = broker.communicate()
    if rc:
        print(stde.decode('utf-8'))
        exit(rc)
