#!/usr/bin/env python3

# Test whether a client correctly handles sending a message with QoS > maximum QoS.

from mosq_test_helper import *

port = mosq_test.get_lib_port()

rc = 1
keepalive = 60
connect_packet = mosq_test.gen_connect("publish-qos2-test", keepalive=keepalive, proto_ver=5)

props = mqtt5_props.gen_byte_prop(mqtt5_props.PROP_MAXIMUM_QOS, 0)
connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5, properties=props)

disconnect_packet = mosq_test.gen_disconnect(proto_ver=5)

publish_1_packet = mosq_test.gen_publish("maximum/qos/qos0", qos=0, payload="message", proto_ver=5)

disconnect_packet = mosq_test.gen_disconnect(proto_ver=5)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.settimeout(10)
sock.bind(('', port))
sock.listen(5)


client_args = sys.argv[1:]
env = dict(os.environ)
env['LD_LIBRARY_PATH'] = mosq_test.get_build_root() + '/lib:' + mosq_test.get_build_root() + '/lib/cpp'
try:
    pp = env['PYTHONPATH']
except KeyError:
    pp = ''
env['PYTHONPATH'] = mosq_test.get_build_root() + '/lib/python:'+pp
client = mosq_test.start_client(filename=sys.argv[1].replace('/', '-'), cmd=client_args, env=env, port=port)


try:
    (conn, address) = sock.accept()
    conn.settimeout(10)

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")
    mosq_test.expect_packet(conn, "publish 1", publish_1_packet)
    mosq_test.expect_packet(conn, "disconnect", disconnect_packet)
    rc = 0

    conn.close()
except mosq_test.TestError:
    pass
finally:
    for i in range(0, 5):
        if client.returncode != None:
            break
        time.sleep(0.1)

    if mosq_test.wait_for_subprocess(client):
        print("test client not finished")
        rc=1
    sock.close()
    if client.returncode != 0:
        exit(1)

exit(rc)
