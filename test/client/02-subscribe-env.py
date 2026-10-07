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

    cmd = [mosq_paths.mosquitto_sub,
            '-p', str(port),
            '-q', '1',
            '-V', V,
            '-C', '1',
            '-d',
            ]

    payload = "783c9cc5-5ad8-433f-a4ee-7dcd978c90a8"
    publish_packet_s = mqtt_packets.gen_publish("env/config/file/sub", qos=1, mid=1, payload=payload, proto_ver=proto_ver, retain=True)
    publish_packet_r = mqtt_packets.gen_publish("env/config/file/sub", qos=1, mid=2, payload=payload, proto_ver=proto_ver, retain=True)
    puback_packet_s = mqtt_packets.gen_puback(1, proto_ver=proto_ver,  reason_code=mqtt5_rc.NO_MATCHING_SUBSCRIBERS)
    puback_packet_r = mqtt_packets.gen_puback(2, proto_ver=proto_ver)

    broker = MosquittoBroker(port=port)
    with broker:
        sock = mosq_test.pub_helper(port=port, proto_ver=proto_ver)
        sock.send(publish_packet_s)
        mosq_test.expect_packet(sock, "puback", puback_packet_s)

        sub = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if payload in sub.stdout:
            rc = sub.returncode
        sock.close()

        if rc:
            print(sub.stdout)
            print(sub.stderr)
            print("proto_ver=%d" % (proto_ver))
            raise ValueError(rc)


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
