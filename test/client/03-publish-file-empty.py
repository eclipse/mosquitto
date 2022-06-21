#!/usr/bin/env python3

#

from mosq_test_helper import *

def write_file(filename):
    with open(filename, 'w') as f:
        pass


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
            'LD_LIBRARY_PATH': mosq_test.get_build_root() + '/lib',
            'XDG_CONFIG_HOME':'/tmp/missing'
            }
    cmd = ['../../client/mosquitto_pub',
            '-p', str(port),
            '-q', '1',
            '-t', '03/pub/file/empty/test',
            '-f', data_file,
            '-V', V
            ]

    publish_packet = mosq_test.gen_publish("03/pub/file/empty/test", qos=0, payload="", proto_ver=proto_ver)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    write_file(data_file)

    try:
        sock = mosq_test.sub_helper(port=port, topic="#", qos=0, proto_ver=proto_ver)

        pub = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
        pub.wait()

        mosq_test.expect_packet(sock, "publish", publish_packet)
        rc = 0
        sock.close()
    except mosq_test.TestError:
        pass
    except Exception as e:
        print(e)
    finally:
        os.remove(data_file)
        broker.terminate()
        broker.wait()
        (stdo, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
            print("proto_ver=%d" % (proto_ver))
            exit(rc)


do_test(proto_ver=3)
do_test(proto_ver=4)
do_test(proto_ver=5)
