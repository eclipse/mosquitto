#!/usr/bin/env python3

# Test whether an anonymous connection is correctly denied.

from mosq_test_helper import *

def write_config1(filename, port):
    with open(filename, 'w') as f:
        f.write("max_connections 10\n") # So the file isn't completely empty

def write_config2(filename, port):
    with open(filename, 'w') as f:
        f.write("port %d\n" % (port))

def write_config3(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))

def write_config4(filename, port):
    with open(filename, 'w') as f:
        f.write("port %d\n" % (port))
        f.write("allow_anonymous true\n")

def write_config5(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")


def do_test(use_conf, write_config, expect_success):
    port = mosq_test.get_port()
    if write_config is not None:
        conf_file = os.path.basename(__file__).replace('.py', '.conf')
        write_config(conf_file, port)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=use_conf, port=port)

    try:
        for proto_ver in [4, 5]:
            rc = 1
            connect_packet = mosq_test.gen_connect("connect-anon-test-%d" % (proto_ver), proto_ver=proto_ver)

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


# No config file - allow_anonymous should be true
do_test(use_conf=False, write_config=None, expect_success=True)

# Config file but no listener - allow_anonymous should be true
# Not possible right now because the test doesn't allow us to use a config file and -p at the same time.
#do_test(use_conf=True, write_config=write_config1, expect_success=True)

# Config file with "port" - allow_anonymous should be false
do_test(use_conf=True, write_config=write_config2, expect_success=False)

# Config file with "listener" - allow_anonymous should be false
do_test(use_conf=True, write_config=write_config3, expect_success=False)

# Config file with "port" - allow_anonymous explicitly true
do_test(use_conf=True, write_config=write_config4, expect_success=True)

# Config file with "listener" - allow_anonymous explicitly true
do_test(use_conf=True, write_config=write_config5, expect_success=True)
exit(0)
