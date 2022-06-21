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
            'LD_LIBRARY_PATH': mosq_test.get_build_root() + '/lib',
            'XDG_CONFIG_HOME':'/tmp/missing'
            }
    cmd = ['../../client/mosquitto_pub',
            '-p', str(port),
            '-q', '2',
            '-t', '03/pub/stdin/line/test',
            '-l',
            '-V', V
            ]

    publish_packet1 = mosq_test.gen_publish("03/pub/stdin/line/test", qos=0, payload="message1", proto_ver=proto_ver)
    publish_packet2 = mosq_test.gen_publish("03/pub/stdin/line/test", qos=0, payload="message2", proto_ver=proto_ver)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.sub_helper(port=port, topic="#", qos=0, proto_ver=proto_ver)

        pub = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
        pub.stdin.write(b'message1\nmessage2')
        pub.stdin.close()
        pub.wait()

        mosq_test.expect_packet(sock, "publish", publish_packet1)
        mosq_test.expect_packet(sock, "publish", publish_packet2)
        rc = 0
        sock.close()
    except mosq_test.TestError:
        pass
    except Exception as e:
        print(e)
    finally:
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
