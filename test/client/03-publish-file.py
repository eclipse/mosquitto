#!/usr/bin/env python3

#

from mosq_test_helper import *

mosq_test.require_features(["WITH_BROKER"])

def write_file(filename):
    with open(filename, 'wb') as f:
        f.write("line1\n".encode('utf-8'))
        f.write("line2\n".encode('utf-8'))


def do_test(proto_ver):
    rc = 1

    port = mosq_test.get_port()
    data_file = os.path.basename(__file__).replace('.py', '.data')

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
            '-t', '03/pub/file/test',
            '-f', data_file,
            '-V', V
            ]

    publish_packet = mqtt_packets.gen_publish("03/pub/file/test", qos=0, payload="line1\nline2\n", proto_ver=proto_ver)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    write_file(data_file)

    try:
        sock = mosq_test.sub_helper(port=port, topic="#", qos=0, proto_ver=proto_ver)

        pub = subprocess.run(cmd, env=env)
        mosq_test.expect_packet(sock, "publish", publish_packet)
        rc = pub.returncode
        sock.close()
    except mosq_test.TestError:
        pass
    except Exception as e:
        print(e)
    finally:
        os.remove(data_file)
        mosq_test.terminate_broker(broker)
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1
        if rc:
            print(mosq_test.broker_log(broker))
            print("proto_ver=%d" % (proto_ver))
            exit(rc)


do_test(proto_ver=3)
do_test(proto_ver=4)
do_test(proto_ver=5)