#!/usr/bin/env python3

# Test whether a client sends a pingreq after the keepalive time

# The client should connect to port 1888 with keepalive=4, clean session set,
# and client id 01-keepalive-pingreq
# The client should send a PINGREQ message after the appropriate amount of time
# (4 seconds after no traffic).

from mosq_test_helper import *

port = mosq_test.get_lib_port()

rc = 1
keepalive = 5
connect_packet = mosq_test.gen_connect("01-keepalive-pingreq", keepalive=keepalive)
connack_packet = mosq_test.gen_connack(rc=0)

pingreq_packet = mosq_test.gen_pingreq()
pingresp_packet = mosq_test.gen_pingresp()

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
    conn.settimeout(keepalive+10)

    mosq_test.do_receive_send(conn, connect_packet, connack_packet, "connect")

    mosq_test.expect_packet(conn, "pingreq", pingreq_packet)
    time.sleep(1.0)
    conn.send(pingresp_packet)

    mosq_test.expect_packet(conn, "pingreq", pingreq_packet)
    conn.close()
    rc = 0

except mosq_test.TestError:
    pass
finally:
    #client.terminate()
    if mosq_test.wait_for_subprocess(client, timeout=20):
        print("test client not finished")
        rc=1
    sock.close()

exit(rc)

