#!/usr/bin/env python3

#

from mosq_test_helper import *

def do_test(proto_ver, env):
    rc = 1

    port = mosq_test.get_port()

    if proto_ver == 5:
        V = 'mqttv5'
    elif proto_ver == 4:
        V = 'mqttv311'
    else:
        V = 'mqttv31'

    env['LD_LIBRARY_PATH'] = mosq_test.get_build_root() + '/lib'
    cmd = ['../../client/mosquitto_sub',
            '-p', str(port),
            '-q', '1',
            '-V', V,
            '-C', '1'
            ]

    payload = "message"
    publish_packet_s = mosq_test.gen_publish("env/config/file/sub", qos=1, mid=1, payload=payload, proto_ver=proto_ver)
    publish_packet_r = mosq_test.gen_publish("env/config/file/sub", qos=1, mid=2, payload=payload, proto_ver=proto_ver)
    puback_packet_s = mosq_test.gen_puback(1, proto_ver=proto_ver)
    puback_packet_r = mosq_test.gen_puback(2, proto_ver=proto_ver)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.pub_helper(port=port, proto_ver=proto_ver)

        sub = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        time.sleep(0.1)
        sock.send(publish_packet_s)
        mosq_test.expect_packet(sock, "puback", puback_packet_s)
        sub_terminate_rc = 0
        if mosq_test.wait_for_subprocess(sub):
            print("sub not terminated")
            sub_terminate_rc = 1
        (stdo, stde) = sub.communicate()
        if stdo.decode('utf-8') == payload + '\n':
            rc = sub_terminate_rc
        sock.close()
    except mosq_test.TestError:
        pass
    except Exception as e:
        print(e)
    finally:
        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1
        (_, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
            print("proto_ver=%d" % (proto_ver))
            exit(rc)


env = {'HOME': mosq_test.get_build_root() + '/test/client/data'}
do_test(proto_ver=3, env=env)
do_test(proto_ver=4, env=env)
do_test(proto_ver=5, env=env)

env = {'XDG_CONFIG_HOME': mosq_test.get_build_root() + '/test/client/data/.config'}
do_test(proto_ver=3, env=env)
do_test(proto_ver=4, env=env)
do_test(proto_ver=5, env=env)
