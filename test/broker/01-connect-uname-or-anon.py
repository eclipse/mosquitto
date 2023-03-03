#!/usr/bin/env python3

# Test whether an anonymous connection is correctly denied.

from mosq_test_helper import *

def write_config(filename, port, allow_anonymous, password_file):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        if allow_anonymous:
            f.write("allow_anonymous true\n")
        else:
            f.write("allow_anonymous false\n")
        if password_file:
            f.write("password_file %s/%s\n" % (Path(__file__).resolve().parent, filename.replace('.conf', '.pwfile')))

def do_test(allow_anonymous, password_file, username, expect_success):
    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port, allow_anonymous, password_file)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    try:
        for proto_ver in [3, 4, 5]:
            rc = 1
            if username:
                connect_packet = mosq_test.gen_connect("connect-test-%d" % (proto_ver), proto_ver=proto_ver, username="user", password="password")
            else:
                connect_packet = mosq_test.gen_connect("connect-test-%d" % (proto_ver), proto_ver=proto_ver)

            if proto_ver == 5:
                if expect_success == True:
                    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)
                else:
                    connack_packet = mosq_test.gen_connack(rc=mqtt5_rc.MQTT_RC_NOT_AUTHORIZED, proto_ver=proto_ver, properties=None)
            else:
                if expect_success == True:
                    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)
                else:
                    connack_packet = mosq_test.gen_connack(rc=5, proto_ver=proto_ver)


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
            print("proto_ver=%d, allow_anonymous=%d, password_file=%d, username=%d" % (proto_ver, allow_anonymous, password_file, username))
            exit(rc)


do_test(allow_anonymous=True,  password_file=True,  username=True,  expect_success=True)
do_test(allow_anonymous=True,  password_file=True,  username=False, expect_success=True)
do_test(allow_anonymous=True,  password_file=False, username=True,  expect_success=True)
do_test(allow_anonymous=True,  password_file=False, username=False, expect_success=True)
do_test(allow_anonymous=False, password_file=True,  username=True,  expect_success=True)
do_test(allow_anonymous=False, password_file=True,  username=False, expect_success=False)
do_test(allow_anonymous=False, password_file=False, username=True,  expect_success=False)
do_test(allow_anonymous=False, password_file=False, username=False, expect_success=False)

exit(0)
