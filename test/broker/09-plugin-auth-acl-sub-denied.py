#!/usr/bin/env python3

# Test topic subscription. All SUBSCRIBE requests are denied. Check this
# produces the correct response, and check the client isn't disconnected (ref:
# issue #1016).

from mosq_test_helper import *

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("auth_plugin c/auth_plugin_acl_sub_denied.so\n")
        f.write("allow_anonymous false\n")

port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
write_config(conf_file, port)

rc = 1
connect_packet = mosq_test.gen_connect("sub-denied-test", username="denied")
connack_packet = mosq_test.gen_connack(rc=0)

mid = 53
subscribe_packet = mosq_test.gen_subscribe(mid, "qos0/test", 0)
suback_packet = mosq_test.gen_suback(mid, 128)

mid_pub = 54
publish_packet = mosq_test.gen_publish("topic", qos=1, payload="test", mid=mid_pub)
puback_packet = mosq_test.gen_puback(mid_pub)

broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

try:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

    mosq_test.do_send_receive(sock, publish_packet, puback_packet, "puback")

    rc = 0

    sock.close()
except mosq_test.TestError:
    pass
finally:
    os.remove(conf_file)
    broker.terminate()
    if mosq_test.wait_for_subprocess(broker):
        print("broker not terminated")
        if rc == 0: rc=1
    (stdo, stde) = broker.communicate()
    if rc:
        print(stde.decode('utf-8'))


exit(rc)
