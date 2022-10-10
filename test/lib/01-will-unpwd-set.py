#!/usr/bin/env python3

# Test whether a client produces a correct connect with a will, username and password.

# The client should connect to port 1888 with keepalive=60, clean session set,
# client id 01-will-unpwd-set , will topic set to "will-topic", will payload
# set to "will message", will qos=2, will retain not set, username set to
# "oibvvwqw" and password set to "#'^2hg9a&nm38*us".

from mosq_test_helper import *

port = mosq_test.get_lib_port()

rc = 1
keepalive = 60
connect_packet = mosq_test.gen_connect("01-will-unpwd-set",
        keepalive=keepalive, username="oibvvwqw", password="#'^2hg9a&nm38*us",
        will_topic="will-topic", will_qos=2, will_payload=b"will message")

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

    mosq_test.expect_packet(conn, "connect", connect_packet)
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

