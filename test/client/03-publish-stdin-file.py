#!/usr/bin/env python3

#

from mosq_test_helper import *

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
    cmd = [mosq_paths.mosquitto_pub,
            '-p', str(port),
            '-q', '1',
            '-t', '03/pub/stdin/file/test',
            '-s',
            '-V', V
            ]

    publish_packet = mqtt_packets.gen_publish("03/pub/stdin/file/test", qos=0, payload="message1\nmessage2", proto_ver=proto_ver)

    sock = mosq_test.sub_helper(port=port, topic="#", qos=0, proto_ver=proto_ver)

    pub = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    pub.stdin.write(b'message1\nmessage2')
    pub.stdin.close()
    pub_terminate_rc = 0
    if mosq_test.wait_for_subprocess(pub):
        print("pub not terminated")
        pub_terminate_rc = 1

    mosq_test.expect_packet(sock, "publish", publish_packet)
    rc = pub_terminate_rc
    sock.close()


if __name__ == '__main__':
    port = mosq_test.get_port()
    broker = MosquittoBroker(port=port)
    with broker:
        do_test(port, proto_ver=3)
        do_test(port, proto_ver=4)
        do_test(port, proto_ver=5)
