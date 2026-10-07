#!/usr/bin/env python3

#

from mosq_test_helper import *
import json

mosq_test.require_features(["WITH_BROKER"])

def do_test(port, proto_ver):
    rc = 1

    if proto_ver == 5:
        V = 'mqttv5'
    elif proto_ver == 4:
        V = 'mqttv311'
    else:
        V = 'mqttv31'

    env = {
        'XDG_CONFIG_HOME':'/tmp/missing'
    }
    env = mosq_test.env_add_ld_library_path(env)
    cmd = [mosq_paths.mosquitto_sub,
            '-p', str(port),
            '-q', '1',
            '-F', '%j',
            '-t', '02/sub/format/json/qos1/test',
            '-V', V,
            '-C', '1'
            ]

    publish_packet = mqtt_packets.gen_publish("02/sub/format/json/qos1/test", mid=1, qos=1, payload="message", proto_ver=proto_ver)

    expected = {"tst": "", "topic": "02/sub/format/json/qos1/test", "qos": 1, "mid": 1, "retain": 0, "payloadlen": 7, "payload": "message"}

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
    sock.close()

    if j == expected:
        rc = sub_terminate_rc
    else:
        print(json.dumps(expected))
        print(json.dumps(j))
    if rc:
        raise ValueError(rc)


if __name__ == '__main__':
    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)
    with broker:
        do_test(port, proto_ver=3)
        do_test(port, proto_ver=4)
        do_test(port, proto_ver=5)
