#!/usr/bin/env python3

# Test whether a SUBSCRIBE to a topic with an invalid UTF-8 topic fails

from mosq_test_helper import *

def do_test(start_broker, proto_ver):
    rc = 1
    mid = 53
    connect_packet = mosq_test.gen_connect("subscribe-invalid-utf8", proto_ver=proto_ver)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    subscribe_packet = mosq_test.gen_subscribe(mid, "invalid/utf8", 0, proto_ver=proto_ver)
    b = list(struct.unpack("B"*len(subscribe_packet), subscribe_packet))
    b[13] = 0 # Topic should never have a 0x0000
    subscribe_packet = struct.pack("B"*len(b), *b)

    port = mosq_test.get_port()
    broker = None
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        if proto_ver == 4:
            try:
                mosq_test.do_send_receive(sock, subscribe_packet, b"", "suback")
            except BrokenPipeError:
                rc = 0
        else:
            disconnect_packet = mosq_test.gen_disconnect(proto_ver=5, reason_code = mqtt5_rc.MQTT_RC_MALFORMED_PACKET)
            mosq_test.do_send_receive(sock, subscribe_packet, disconnect_packet, "suback")
            rc = 0

        sock.close()
    finally:
        if broker:
            broker.terminate()
            if mosq_test.wait_for_subprocess(broker):
                print("broker not terminated")
                if rc == 0: rc=1
            (stdo, stde) = broker.communicate()
            if rc:
                print(stde.decode('utf-8'))
                print("proto_ver=%d" % (proto_ver))
    return rc


def all_tests(start_broker=False):
    rc = do_test(start_broker, proto_ver=4)
    if rc:
        return rc
    rc = do_test(start_broker, proto_ver=5)
    if rc:
        return rc
    return 0

if __name__ == '__main__':
    sys.exit(all_tests(True))
