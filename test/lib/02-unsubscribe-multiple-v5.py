#!/usr/bin/env python3

# Test whether a v5 client sends a correct UNSUBSCRIBE packet with multiple
# topics, and handles the UNSUBACK.

from mosq_test_helper import *

port = mosq_test.get_lib_port()

keepalive = 60
connect_packet = mosq_test.gen_connect("unsubscribe-test", keepalive=keepalive, proto_ver=5)
connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

disconnect_packet = mosq_test.gen_disconnect(proto_ver=5)

mid = 1
subscribe_packet = mosq_test.gen_subscribe(mid, "unsubscribe/test", 2, proto_ver=5)
suback_packet = mosq_test.gen_suback(mid, 2, proto_ver=5)

mid = 2
unsubscribe_packet = mosq_test.gen_unsubscribe_multiple(mid, ["unsubscribe/test", "no-sub"], proto_ver=5)
unsuback_packet = mosq_test.gen_unsuback(mid, reason_code=[0, 17], proto_ver=5)

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

rc = 1
try:
    (conn, address) = sock.accept()
    conn.settimeout(10)

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")
    mosq_test.do_receive_send(conn, subscribe_packet, suback_packet, "subscribe")
    mosq_test.do_receive_send(conn, unsubscribe_packet, unsuback_packet, "unsubscribe")
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
