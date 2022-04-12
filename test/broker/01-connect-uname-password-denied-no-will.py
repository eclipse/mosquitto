#!/usr/bin/env python3

# Test whether a connection is denied if it provides a correct username but
# incorrect password. The client has a will, but it should not be sent. Check that.

from mosq_test_helper import *

def write_config(filename, port, pw_file):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("password_file %s\n" % (pw_file))
        f.write("allow_anonymous false\n")

def write_pwfile(filename):
    with open(filename, 'w') as f:
        # Username user, password password
        f.write('user:$6$vZY4TS+/HBxHw38S$vvjVFECzb8dyuu/mruD2QKTfdFn0WmKxbc+1TsdB0L8EdHk3v9JRmfjHd56+VaTnUcSZOZ/hzkdvWCtxlX7AUQ==\n')


def do_test(proto_ver):
    pw_file = os.path.basename(__file__).replace('.py', '.pwfile')
    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port, pw_file)
    write_pwfile(pw_file)

    rc = 1
    connect1_packet = mosq_test.gen_connect("connect-uname-pwd-test", username="user", password="password", will_topic="will/test", will_payload=b"will msg", proto_ver=proto_ver)
    connack1_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    mid = 1
    subscribe_packet = mosq_test.gen_subscribe(mid, topic="will/test", qos=0, proto_ver=proto_ver)
    suback_packet = mosq_test.gen_suback(mid, 0, proto_ver=proto_ver)

    connect2_packet = mosq_test.gen_connect("connect-uname-pwd-test", username="user", password="password9", proto_ver=proto_ver)
    if proto_ver == 5:
        connack2_packet = mosq_test.gen_connack(rc=mqtt5_rc.MQTT_RC_NOT_AUTHORIZED, proto_ver=proto_ver, properties=None)
    else:
        connack2_packet = mosq_test.gen_connack(rc=5, proto_ver=proto_ver)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    try:
        sock1 = mosq_test.do_client_connect(connect1_packet, connack1_packet, port=port)
        mosq_test.do_send_receive(sock1, subscribe_packet, suback_packet)

        sock2 = mosq_test.do_client_connect(connect2_packet, connack2_packet, port=port)
        sock2.close()

        # If we receive a will here, this is an error
        mosq_test.do_ping(sock1)
        sock1.close()
        rc = 0

    except mosq_test.TestError:
        pass
    finally:
        os.remove(conf_file)
        os.remove(pw_file)
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
