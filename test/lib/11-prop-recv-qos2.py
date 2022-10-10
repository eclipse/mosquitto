#!/usr/bin/env python3

# Check whether the v5 message callback gets the properties

from mosq_test_helper import *

port = mosq_test.get_lib_port()

rc = 1
keepalive = 60
connect_packet = mosq_test.gen_connect("prop-test", keepalive=keepalive, proto_ver=5)
connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)


mid = 1
props = mqtt5_props.gen_string_prop(mqtt5_props.PROP_CONTENT_TYPE, "plain/text")
props += mqtt5_props.gen_string_prop(mqtt5_props.PROP_RESPONSE_TOPIC, "msg/123")
publish_packet = mosq_test.gen_publish("prop/test", mid=mid, qos=2, payload="message", proto_ver=5, properties=props)
pubrec_packet = mosq_test.gen_pubrec(mid=mid, proto_ver=5)
pubrel_packet = mosq_test.gen_pubrel(mid=mid, proto_ver=5)
pubcomp_packet = mosq_test.gen_pubcomp(mid=mid, proto_ver=5)

ok_packet = mosq_test.gen_publish("ok", qos=0, payload="ok", proto_ver=5)

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
    mosq_test.do_send_receive(conn, publish_packet, pubrec_packet, "pubrec")
    mosq_test.do_send_receive(conn, pubrel_packet, pubcomp_packet, "pubcomp")
    mosq_test.expect_packet(conn, "ok", ok_packet)
    rc = 0

    conn.close()
except mosq_test.TestError:
    pass
finally:
    if mosq_test.wait_for_subprocess(client):
        print("test client not finished")
        rc=1
    if rc:
        (stdo, stde) = client.communicate()
        print(stde)
    sock.close()

exit(rc)
