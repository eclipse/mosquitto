#!/usr/bin/env python

# Test whether a UNSUBSCRIBE with no topic results in a disconnect. MQTT-3.10.3-2

import inspect, os, sys
import struct

def gen_unsubscribe_invalid_no_topic(mid):
    pack_format = "!BBH"
    return struct.pack(pack_format, 162, 2, mid)

# From http://stackoverflow.com/questions/279237/python-import-a-module-from-a-folder
cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile( inspect.currentframe() ))[0],"..")))
if cmd_subfolder not in sys.path:
    sys.path.insert(0, cmd_subfolder)

import mosq_test

rc = 1
mid = 3
keepalive = 60
connect_packet = mosq_test.gen_connect("unsubscribe-invalid-no-topic-test", keepalive=keepalive, proto_ver=4)
connack_packet = mosq_test.gen_connack(rc=0)

unsubscribe_packet = gen_unsubscribe_invalid_no_topic(mid)

cmd = ['../../src/mosquitto', '-p', '1888']
broker = mosq_test.start_broker(filename=os.path.basename(__file__), cmd=cmd)

try:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet)
    sock.send(unsubscribe_packet)

    if mosq_test.expect_packet(sock, "disconnect", ""):
        rc = 0

    sock.close()
finally:
    broker.terminate()
    broker.wait()
    if rc:
        (stdo, stde) = broker.communicate()
        print(stde)

exit(rc)

