#!/usr/bin/env python3

#

from mosq_test_helper import *
import platform

mosq_test.require_features(["WITH_BROKER"])

def do_test(proto_ver, configenv):
    rc = 1

    port = mosq_test.get_port()

    if proto_ver == 5:
        V = 'mqttv5'
    elif proto_ver == 4:
        V = 'mqttv311'
    else:
        V = 'mqttv31'

    env = mosq_test.env_add_ld_library_path()
    for e in ['XDG_CONFIG_HOME', 'HOME', 'USERPROFILE']:
        try:
            del env[e]
        except KeyError:
            pass
    env.update(configenv)
    cmd = [mosq_paths.mosquitto_pub,
            '-p', str(port),
            '-q', '1',
            '-V', V,
            '-d',
            ]

    mid = 1
    publish_packet = mqtt_packets.gen_publish("env/config/file/pub", qos=1, mid=mid, payload="message", proto_ver=proto_ver)
    if proto_ver == 5:
        puback_packet = mqtt_packets.gen_puback(mid, proto_ver=proto_ver, reason_code=mqtt5_rc.NO_MATCHING_SUBSCRIBERS)
    else:
        puback_packet = mqtt_packets.gen_puback(mid, proto_ver=proto_ver)

    broker = MosquittoBroker(port=port)

    with broker:
        sock = mosq_test.sub_helper(port=port, topic="#", qos=1, proto_ver=proto_ver)

        pub = subprocess.run(cmd, capture_output=True, text=True, env=env)

        mosq_test.expect_packet(sock, "publish", publish_packet)
        rc = pub.returncode
        sock.close()

        if rc:
            print(pub.stdout)
            print(pub.stderr)
            print("proto_ver=%d" % (proto_ver))


if platform.system() == 'Windows':
    env = {'USERPROFILE': str(source_dir / 'data' / '.config')}
    do_test(proto_ver=3, configenv=env)
    do_test(proto_ver=4, configenv=env)
    do_test(proto_ver=5, configenv=env)
else:
    env = {'HOME': str(source_dir / 'data')}
    do_test(proto_ver=3, configenv=env)
    do_test(proto_ver=4, configenv=env)
    do_test(proto_ver=5, configenv=env)

    env = {'XDG_CONFIG_HOME': str(source_dir / 'data' / '.config')}
    do_test(proto_ver=3, configenv=env)
    do_test(proto_ver=4, configenv=env)
    do_test(proto_ver=5, configenv=env)
