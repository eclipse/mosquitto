#!/usr/bin/env python3

# Test whether config files with windows line endings are accepted.
# This just connects anonymously - if the config file causes a failure, the
# broker won't start so the connection would fail.

from mosq_test_helper import *

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\r\n" % (port))
        f.write("allow_anonymous true\r\n")

def do_test():
    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    try:
        for proto_ver in [4, 5]:
            rc = 1
            connect_packet = mosq_test.gen_connect("connect-anon-test-%d" % (proto_ver), proto_ver=proto_ver)

            if proto_ver == 5:
                connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)
            else:
                connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

            sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
            sock.close()
            rc = 0
    except mosq_test.TestError:
        pass
    finally:
        os.remove(conf_file)
        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1
        (stdo, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
            print("proto_ver=%d" % (proto_ver))
            exit(rc)


do_test()
exit(0)
