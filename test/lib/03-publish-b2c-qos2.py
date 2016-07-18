#!/usr/bin/env python

# Test whether a client responds correctly to a PUBLISH with QoS 1.

# The client should connect to port 1888 with keepalive=60, clean session set,
# and client id publish-qos2-test
# The test will send a CONNACK message to the client with rc=0. Upon receiving
# the CONNACK the client should verify that rc==0.
# The test will send the client a PUBLISH message with topic
# "pub/qos2/receive", payload of "message", QoS=2 and mid=13423. The client
# should handle this as per the spec by sending a PUBREC message.
# The test will not respond to the first PUBREC message, so the client must
# resend the PUBREC message with dup=1. Note that to keep test durations low, a
# message retry timeout of less than 10 seconds is required for this test.
# On receiving the second PUBREC with dup==1, the test will send the correct
# PUBREL message. The client should respond to this with the correct PUBCOMP
# message and then exit with return code=0.

import inspect
import os
import socket
import sys
import time

# From http://stackoverflow.com/questions/279237/python-import-a-module-from-a-folder
cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile( inspect.currentframe() ))[0],"..")))
if cmd_subfolder not in sys.path:
    sys.path.insert(0, cmd_subfolder)

import mosq_test

rc = 1
keepalive = 60
connect_packet = mosq_test.gen_connect("publish-qos2-test", keepalive=keepalive)
connack_packet = mosq_test.gen_connack(rc=0)

disconnect_packet = mosq_test.gen_disconnect()

mid = 13423
publish_packet = mosq_test.gen_publish("pub/qos2/receive", qos=2, mid=mid, payload="message")
pubrec_packet = mosq_test.gen_pubrec(mid)
pubrel_packet = mosq_test.gen_pubrel(mid)
pubcomp_packet = mosq_test.gen_pubcomp(mid)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.settimeout(10)
sock.bind(('', 1888))
sock.listen(5)

client_args = sys.argv[1:]
env = dict(os.environ)
env['LD_LIBRARY_PATH'] = '../../lib:../../lib/cpp'
try:
    pp = env['PYTHONPATH']
except KeyError:
    pp = ''
env['PYTHONPATH'] = '../../lib/python:'+pp
client = mosq_test.start_client(filename=sys.argv[1].replace('/', '-'), cmd=client_args, env=env)

try:
    (conn, address) = sock.accept()
    conn.settimeout(10)

    if mosq_test.expect_packet(conn, "connect", connect_packet):
        conn.send(connack_packet)
        conn.send(publish_packet)

        if mosq_test.expect_packet(conn, "pubrec", pubrec_packet):
            conn.send(pubrel_packet)

            if mosq_test.expect_packet(conn, "pubcomp", pubcomp_packet):
                rc = 0

    conn.close()
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
