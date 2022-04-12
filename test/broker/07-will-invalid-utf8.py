#!/usr/bin/env python3

# Test whether a will topic with invalid UTF-8 fails

from mosq_test_helper import *

def do_test(start_broker, proto_ver):
    rc = 1
    mid = 53
    connect_packet = mosq_test.gen_connect("will-invalid-utf8", will_topic="will/invalid/utf8", proto_ver=proto_ver)

    b = list(struct.unpack("B"*len(connect_packet), connect_packet))
    b[40] = 0 # Topic should never have a 0x0000
    connect_packet = struct.pack("B"*len(b), *b)

    port = mosq_test.get_port()
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, b"", timeout=30, port=port)
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
                print("proto_ver=%d" % (proto_ver))
                exit(rc)
        else:
            return rc


def all_tests(start_broker=False):
    rc = do_test(start_broker, proto_ver=4)
    if rc:
        return rc;
    rc = do_test(start_broker, proto_ver=5)
    if rc:
        return rc;
    return 0

if __name__ == '__main__':
    all_tests(True)
