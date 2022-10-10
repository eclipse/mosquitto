#!/usr/bin/env python3

from mosq_test_helper import *

port = mosq_test.get_port()

rc = 1
connect_packet = mosq_test.gen_connect("test-helper")
connack_packet = mosq_test.gen_connack(rc=0)

publish_packet = mosq_test.gen_publish("bridge/ssl/test", qos=0, payload="message")

disconnect_packet = mosq_test.gen_disconnect()

sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port, connack_error="helper connack")
sock.send(publish_packet)
sock.send(disconnect_packet)
sock.close()

exit(0)
