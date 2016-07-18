#!/usr/bin/env python

import subprocess
import socket

import inspect, os, sys
# From http://stackoverflow.com/questions/279237/python-import-a-module-from-a-folder
cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile( inspect.currentframe() ))[0],"..")))
if cmd_subfolder not in sys.path:
    sys.path.insert(0, cmd_subfolder)

import mosq_test

rc = 1
mid = 3265
keepalive = 60
connect_packet = mosq_test.gen_connect("pub-qos1-disco-test", keepalive=keepalive, clean_session=False)
connack1_packet = mosq_test.gen_connack(resv=0, rc=0)
connack2_packet = mosq_test.gen_connack(resv=1, rc=0)

subscribe_packet = mosq_test.gen_subscribe(mid, "qos1/disconnect/test", 1)
suback_packet = mosq_test.gen_suback(mid, 1)

mid = 1
publish_packet = mosq_test.gen_publish("qos1/disconnect/test", qos=1, mid=mid, payload="disconnect-message")
publish_dup_packet = mosq_test.gen_publish("qos1/disconnect/test", qos=1, mid=mid, payload="disconnect-message", dup=True)
puback_packet = mosq_test.gen_puback(mid)

mid = 3266
publish2_packet = mosq_test.gen_publish("qos1/outgoing", qos=1, mid=mid, payload="outgoing-message")
puback2_packet = mosq_test.gen_puback(mid)

broker = mosq_test.start_broker(filename=os.path.basename(__file__))

try:
    sock = mosq_test.do_client_connect(connect_packet, connack1_packet)
    sock.send(subscribe_packet)

    if mosq_test.expect_packet(sock, "suback", suback_packet):
        pub = subprocess.Popen(['./03-publish-b2c-disconnect-qos1-helper.py'])
        pub.wait()
        # Should have now received a publish command

        if mosq_test.expect_packet(sock, "publish", publish_packet):
            # Send our outgoing message. When we disconnect the broker
            # should get rid of it and assume we're going to retry.
            sock.send(publish2_packet)
            sock.close()

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(60) # 60 seconds timeout is much longer than 5 seconds message retry.
            sock.connect(("localhost", 1888))
            sock.send(connect_packet)

            if mosq_test.expect_packet(sock, "connack", connack2_packet):

                if mosq_test.expect_packet(sock, "dup publish", publish_dup_packet):
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

