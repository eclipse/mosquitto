#!/usr/bin/env python3

# Test whether a client produces a correct connect and subsequent disconnect, with a will, MQTT v5

from mosq_test_helper import *

port = mosq_test.get_lib_port()

rc = 1
keepalive = 60
props = mqtt5_props.gen_byte_prop(mqtt5_props.PROP_PAYLOAD_FORMAT_INDICATOR, 0x01)
connect_packet = mosq_test.gen_connect("01-con-discon-will", keepalive=keepalive, will_topic="will/topic", will_payload=b"will-payload", will_qos=1, will_retain=True, will_properties=props, proto_ver=5)
connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

disconnect_packet = mosq_test.gen_disconnect()

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
    mosq_test.expect_packet(conn, "disconnect", disconnect_packet)
    rc = 0

    conn.close()
except mosq_test.TestError:
    pass
finally:
    if mosq_test.wait_for_subprocess(client):
        print("test client not finished")
        rc=1
    sock.close()

exit(rc)

