#!/usr/bin/env python3

#

from mosq_test_helper import *

def do_test(proto_ver):
    rc = 1

    port = mosq_test.get_port()

    if proto_ver == 5:
        V = 'mqttv5'
    elif proto_ver == 4:
        V = 'mqttv311'
    else:
        V = 'mqttv31'

    env = {
            'LD_LIBRARY_PATH':'../../lib',
            'XDG_CONFIG_HOME':'/tmp/missing'
            }
    cmd = ['../../client/mosquitto_sub',
            '-p', str(port),
            '-q', '1',
            '-t', '02/sub/null/test',
            '-V', V,
            '-C', '1',
            '-v'
            ]

    topic = "02/sub/null/test"
    payload = ""
    publish_packet_s = mosq_test.gen_publish(topic, qos=1, mid=1, payload=payload, proto_ver=proto_ver)
    publish_packet_r = mosq_test.gen_publish(topic, qos=1, mid=2, payload=payload, proto_ver=proto_ver)
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
        expected_output = topic + ' (null)\n'
        if stdo.decode('utf-8') == expected_output:
            rc = sub_terminate_rc
        else:
            print("expected: %s" % expected_output)
            print("actual:   %s"  % stdo.decode('utf-8'))
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
        (stdo, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
            print("proto_ver=%d" % (proto_ver))
            exit(rc)


do_test(proto_ver=3)
do_test(proto_ver=4)
do_test(proto_ver=5)
