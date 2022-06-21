#!/usr/bin/env python3

# Test whether a client produces a correct connect and subsequent disconnect.

# The client should connect to port 1888 with keepalive=60, clean session set,
# and client id 01-con-discon-success
# The test will send a CONNACK message to the client with rc=0. Upon receiving
# the CONNACK and verifying that rc=0, the client should send a DISCONNECT
# message. If rc!=0, the client should exit with an error.

from mosq_test_helper import *

port = mosq_test.get_lib_port()

rc = 1
keepalive = 60
props = mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_MAXIMUM_PACKET_SIZE, 1000)
props += mqtt5_props.gen_uint16_prop(mqtt5_props.PROP_RECEIVE_MAXIMUM, 20)
connect_packet = mosq_test.gen_connect("01-con-discon-success-v5", keepalive=keepalive, proto_ver=5, properties=props)
connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

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
    mosq_test.expect_packet(conn, "disconnect", disconnect_packet)
    rc = 0

    conn.close()
except mosq_test.TestError:
    pass
finally:
    client.wait()
    sock.close()

exit(rc)

