#!/usr/bin/env python

import inspect, os, sys
# From http://stackoverflow.com/questions/279237/python-import-a-module-from-a-folder
cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile( inspect.currentframe() ))[0],"..")))
if cmd_subfolder not in sys.path:
    sys.path.insert(0, cmd_subfolder)

import mosq_test

rc = 1
mid = 3265
keepalive = 60
connect_packet = mosq_test.gen_connect("pub-qos2-disco-test", keepalive=keepalive, clean_session=False, proto_ver=3)
connack_packet = mosq_test.gen_connack(resv=0, rc=0)

subscribe_packet = mosq_test.gen_subscribe(mid, "qos2/disconnect/test", 2)
suback_packet = mosq_test.gen_suback(mid, 2)

mid = 1
publish_packet = mosq_test.gen_publish("qos2/disconnect/test", qos=2, mid=mid, payload="disconnect-message")
publish_dup_packet = mosq_test.gen_publish("qos2/disconnect/test", qos=2, mid=mid, payload="disconnect-message", dup=True)
pubrec_packet = mosq_test.gen_pubrec(mid)
pubrel_packet = mosq_test.gen_pubrel(mid)
pubrel_dup_packet = mosq_test.gen_pubrel(mid, dup=True)
pubcomp_packet = mosq_test.gen_pubcomp(mid)

broker = mosq_test.start_broker(filename=os.path.basename(__file__))

try:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet)

    sock.send(publish_packet)
    if mosq_test.expect_packet(sock, "pubrec", pubrec_packet):
        # We're now going to disconnect and pretend we didn't receive the pubrec.
        sock.close()

        sock = mosq_test.do_client_connect(connect_packet, connack_packet)
        sock.send(publish_dup_packet)

        if mosq_test.expect_packet(sock, "pubrec", pubrec_packet):
            sock.send(pubrel_packet)

            if mosq_test.expect_packet(sock, "pubcomp", pubcomp_packet):
                # Again, pretend we didn't receive this pubcomp
                sock.close()

                sock = mosq_test.do_client_connect(connect_packet, connack_packet)
                sock.send(pubrel_dup_packet)

                if mosq_test.expect_packet(sock, "pubcomp", pubcomp_packet):
                    rc = 0

                sock.close()
finally:
    broker.terminate()
    broker.wait()
    if rc:
        (stdo, stde) = broker.communicate()
        print(stde)

exit(rc)

