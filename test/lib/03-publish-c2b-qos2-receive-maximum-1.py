#!/usr/bin/env python3

# Test whether a client responds correctly to multiple PUBLISH with QoS 2, with
# receive maximum set to 1.

from mosq_test_helper import *

port = mosq_test.get_lib_port()

rc = 1
keepalive = 60
connect_packet = mosq_test.gen_connect("publish-qos2-test", keepalive=keepalive, proto_ver=5)

props = mqtt5_props.gen_uint16_prop(mqtt5_props.PROP_RECEIVE_MAXIMUM, 1)
connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5, properties=props, property_helper=False)

disconnect_packet = mosq_test.gen_disconnect(proto_ver=5)

mid = 1
publish_1_packet = mosq_test.gen_publish("topic", qos=2, mid=mid, payload="12345", proto_ver=5)
pubrec_1_packet = mosq_test.gen_pubrec(mid, proto_ver=5)
pubrel_1_packet = mosq_test.gen_pubrel(mid, proto_ver=5)
pubcomp_1_packet = mosq_test.gen_pubcomp(mid, proto_ver=5)

mid = 2
publish_2_packet = mosq_test.gen_publish("topic", qos=2, mid=mid, payload="12345", proto_ver=5)
pubrec_2_packet = mosq_test.gen_pubrec(mid, proto_ver=5)
pubrel_2_packet = mosq_test.gen_pubrel(mid, proto_ver=5)
pubcomp_2_packet = mosq_test.gen_pubcomp(mid, proto_ver=5)

mid = 3
publish_3_packet = mosq_test.gen_publish("topic", qos=2, mid=mid, payload="12345", proto_ver=5)
pubrec_3_packet = mosq_test.gen_pubrec(mid, proto_ver=5)
pubrel_3_packet = mosq_test.gen_pubrel(mid, proto_ver=5)
pubcomp_3_packet = mosq_test.gen_pubcomp(mid, proto_ver=5)

mid = 4
publish_4_packet = mosq_test.gen_publish("topic", qos=2, mid=mid, payload="12345", proto_ver=5)
pubrec_4_packet = mosq_test.gen_pubrec(mid, proto_ver=5)
pubrel_4_packet = mosq_test.gen_pubrel(mid, proto_ver=5)
pubcomp_4_packet = mosq_test.gen_pubcomp(mid, proto_ver=5)

mid = 5
publish_5_packet = mosq_test.gen_publish("topic", qos=2, mid=mid, payload="12345", proto_ver=5)
pubrec_5_packet = mosq_test.gen_pubrec(mid, proto_ver=5)
pubrel_5_packet = mosq_test.gen_pubrel(mid, proto_ver=5)
pubcomp_5_packet = mosq_test.gen_pubcomp(mid, proto_ver=5)


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.settimeout(10)
sock.bind(('', port))
sock.listen(5)


client_args = sys.argv[1:]
env = dict(os.environ)
env['LD_LIBRARY_PATH'] = '../../lib:../../lib/cpp'
try:
    pp = env['PYTHONPATH']
except KeyError:
    pp = ''
env['PYTHONPATH'] = '../../lib/python:'+pp
client = mosq_test.start_client(filename=sys.argv[1].replace('/', '-'), cmd=client_args, env=env, port=port)


try:
    (conn, address) = sock.accept()
    conn.settimeout(10)

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")

    mosq_test.do_receive_send(conn, publish_1_packet, pubrec_1_packet, "publish 1")
    mosq_test.do_receive_send(conn, pubrel_1_packet, pubcomp_1_packet, "pubrel 1")

    mosq_test.do_receive_send(conn, publish_2_packet, pubrec_2_packet, "publish 2")
    mosq_test.do_receive_send(conn, pubrel_2_packet, pubcomp_2_packet, "pubrel 2")

    mosq_test.do_receive_send(conn, publish_3_packet, pubrec_3_packet, "publish 3")
    mosq_test.do_receive_send(conn, pubrel_3_packet, pubcomp_3_packet, "pubrel 3")

    mosq_test.do_receive_send(conn, publish_4_packet, pubrec_4_packet, "publish 4")
    mosq_test.do_receive_send(conn, pubrel_4_packet, pubcomp_4_packet, "pubrel 4")

    mosq_test.do_receive_send(conn, publish_5_packet, pubrec_5_packet, "publish 5")
    mosq_test.do_receive_send(conn, pubrel_5_packet, pubcomp_5_packet, "pubrel 5")

    rc = 0

    conn.close()
except mosq_test.TestError:
    pass
finally:
    for i in range(0, 5):
        if client.returncode != None:
            break
        time.sleep(0.1)

    try:
        client.terminate()
    except OSError:
        pass

    client.wait()
    sock.close()
    if client.returncode != 0:
        exit(1)

exit(rc)
