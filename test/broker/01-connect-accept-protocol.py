#!/usr/bin/env python3

# Test accept_protocol_version option

from mosq_test_helper import *

def write_config(filename, port, accept):
    with open(filename, 'w') as f:
        f.write("listener %s\n" % (port))
        f.write("allow_anonymous true\n")
        f.write("accept_protocol_versions %s\n" % (accept))

def do_test(accept, expect_success):
    port = mosq_test.get_port()

    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port, accept)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    try:
        for proto_ver in [3, 4, 5]:
            rc = 1
            connect_packet = mosq_test.gen_connect("accept-protocol-test-%d" % (proto_ver), proto_ver=proto_ver)

            if proto_ver == 5:
                if proto_ver in expect_success:
                    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)
                else:
                    connack_packet = mosq_test.gen_connack(rc=mqtt5_rc.MQTT_RC_UNSUPPORTED_PROTOCOL_VERSION, proto_ver=proto_ver, properties=None)
            else:
                if proto_ver in expect_success:
                    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)
                else:
                    connack_packet = mosq_test.gen_connack(rc=1, proto_ver=proto_ver)


            sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
            sock.close()
            rc = 0
    except mosq_test.TestError:
        pass
    finally:
        if write_config is not None:
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


do_test(accept="3,4,5", expect_success=[3, 4, 5])
do_test(accept="5,4,3", expect_success=[3, 4, 5])
do_test(accept="3 ,4, 5", expect_success=[3, 4, 5])
do_test(accept="    ,   3   ,    4  ,   5    ", expect_success=[3, 4, 5])
do_test(accept="3", expect_success=[3])
do_test(accept="4", expect_success=[4])
do_test(accept="5", expect_success=[5])
do_test(accept="3,4", expect_success=[3, 4])
do_test(accept="3,5", expect_success=[3, 5])
do_test(accept="4,3", expect_success=[3, 4])
do_test(accept="4,5", expect_success=[4, 5])
do_test(accept="5,3", expect_success=[3, 5])
