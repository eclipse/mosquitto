#!/usr/bin/env python

# Test whether a clean session client has a QoS 1 message queued for it.

import subprocess

import inspect, os, sys
# From http://stackoverflow.com/questions/279237/python-import-a-module-from-a-folder
cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile( inspect.currentframe() ))[0],"..")))
if cmd_subfolder not in sys.path:
    sys.path.insert(0, cmd_subfolder)

import mosq_test

rc = 1
mid = 109
keepalive = 60
connect_packet = mosq_test.gen_connect("clean-qos2-test", keepalive=keepalive, clean_session=False)
connack1_packet = mosq_test.gen_connack(resv=0, rc=0)
connack2_packet = mosq_test.gen_connack(resv=1, rc=0)

disconnect_packet = mosq_test.gen_disconnect()

subscribe_packet = mosq_test.gen_subscribe(mid, "qos1/clean_session/test", 1)
suback_packet = mosq_test.gen_suback(mid, 1)

mid = 1
publish_packet = mosq_test.gen_publish("qos1/clean_session/test", qos=1, mid=mid, payload="clean-session-message")
puback_packet = mosq_test.gen_puback(mid)

cmd = ['../../src/mosquitto', '-p', '1888']
broker = mosq_test.start_broker(filename=os.path.basename(__file__), cmd=cmd)

try:
    sock = mosq_test.do_client_connect(connect_packet, connack1_packet)
    sock.send(subscribe_packet)

    if mosq_test.expect_packet(sock, "suback", suback_packet):
        sock.send(disconnect_packet)
        sock.close()

        pub = subprocess.Popen(['./05-clean-session-qos1-helper.py'])
        pub.wait()

        # Now reconnect and expect a publish message.
        sock = mosq_test.do_client_connect(connect_packet, connack2_packet, timeout=30)
        if mosq_test.expect_packet(sock, "publish", publish_packet):
            sock.send(puback_packet)
            rc = 0

        sock.close()
finally:
    broker.terminate()
    broker.wait()
    if rc:
        (stdo, stde) = broker.communicate()
        print(stde)

exit(rc)

