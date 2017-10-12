#!/usr/bin/env python

# Test whether a CONNECT with reserved set to 1 results in a disconnect. MQTT-3.1.2-3

import inspect, os, sys
# From http://stackoverflow.com/questions/279237/python-import-a-module-from-a-folder
cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile( inspect.currentframe() ))[0],"..")))
if cmd_subfolder not in sys.path:
    sys.path.insert(0, cmd_subfolder)

import mosq_test

rc = 1
keepalive = 10
connect_packet = mosq_test.gen_connect("connect-invalid-test", keepalive=keepalive, connect_reserved=True, proto_ver=4)

cmd = ['../../src/mosquitto', '-p', '1888']
broker = mosq_test.start_broker(filename=os.path.basename(__file__), cmd=cmd)

try:
    sock = mosq_test.do_client_connect(connect_packet, "")
    sock.close()
    rc = 0

finally:
    broker.terminate()
    broker.wait()
    if rc:
        (stdo, stde) = broker.communicate()
        print(stde)

exit(rc)

