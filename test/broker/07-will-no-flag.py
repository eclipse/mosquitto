#!/usr/bin/env python3

# Test whether a connection is disconnected if it sets the will flag but does
# not provide a will payload.

from mosq_test_helper import *

def do_test(start_broker, proto_ver):
    rc = 1
    connect_packet = mosq_test.gen_connect("will-no-payload", will_topic="will/topic", will_qos=1, will_retain=True, proto_ver=proto_ver)
    b = list(struct.unpack("B"*len(connect_packet), connect_packet))

    bmod = b[0:len(b)-2]
    bmod[1] = bmod[1] - 2 # Reduce remaining length by two to remove final two payload length values

    connect_packet = struct.pack("B"*len(bmod), *bmod)

    port = mosq_test.get_port()
    broker = None
    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.do_client_connect(connect_packet, b"", port=port)
        sock.close()
    except BrokenPipeError:
        rc = 0
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
    return do_test(start_broker, proto_ver=5)

if __name__ == '__main__':
    sys.exit(all_tests(True))
