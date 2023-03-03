#!/usr/bin/env python3

#

from mosq_test_helper import *
import json

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
            'LD_LIBRARY_PATH': mosq_test.get_build_root() + '/lib',
            'XDG_CONFIG_HOME':'/tmp/missing'
            }
    cmd = ['../../client/mosquitto_sub',
            '-p', str(port),
            '-q', '1',
            '-F', '%j',
            '-t', '02/sub/format/json/qos1/test',
            '-V', V,
            '-C', '1'
            ]

    publish_packet = mosq_test.gen_publish("02/sub/format/json/qos1/test", mid=1, qos=1, payload="message", proto_ver=proto_ver)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    expected = {"tst": "", "topic": "02/sub/format/json/qos1/test", "qos": 1, "mid": 1, "retain": 0, "payloadlen": 7, "payload": "message"}

    try:
        sock = mosq_test.pub_helper(port=port, proto_ver=proto_ver)

        sub = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        time.sleep(0.1)
        sock.send(publish_packet)
        sub_terminate_rc = 0
        if mosq_test.wait_for_subprocess(sub):
            print("sub not terminated")
            sub_terminate_rc = 1
        (stdo, stde) = sub.communicate()
        j = json.loads(stdo.decode('utf-8'))
        j['tst'] = ""

        if j == expected:
            rc = sub_terminate_rc
        else:
            print(json.dumps(expected))
            print(json.dumps(j))
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
