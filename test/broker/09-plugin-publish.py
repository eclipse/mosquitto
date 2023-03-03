#!/usr/bin/env python3

from mosq_test_helper import *

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("auth_plugin c/auth_plugin_publish.so\n")
        f.write("allow_anonymous true\n")

proto_ver = 5
port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
write_config(conf_file, port)

rc = 1
connect1_packet = mosq_test.gen_connect("test-client", username="readwrite", clean_session=False, proto_ver=proto_ver)
connack1_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

publish_packet = mosq_test.gen_publish("init", qos=0, proto_ver=proto_ver)

publish0_packet = mosq_test.gen_publish("topic/0", qos=0, payload="test-message-0", proto_ver=proto_ver)

mid = 1
publish1_packet = mosq_test.gen_publish("topic/1", qos=1, mid=mid, payload="test-message-1", proto_ver=proto_ver)
puback1_packet = mosq_test.gen_puback(mid, proto_ver=proto_ver)

mid = 2
publish2_packet = mosq_test.gen_publish("topic/2", qos=2, mid=mid, payload="test-message-2", proto_ver=proto_ver)
pubrec2_packet = mosq_test.gen_pubrec(mid, proto_ver=proto_ver)
pubrel2_packet = mosq_test.gen_pubrel(mid, proto_ver=proto_ver)
pubcomp2_packet = mosq_test.gen_pubcomp(mid, proto_ver=proto_ver)


props = mqtt5_props.gen_byte_prop(mqtt5_props.PROP_PAYLOAD_FORMAT_INDICATOR, 1)
publish0p_packet = mosq_test.gen_publish("topic/0", qos=0, payload="test-message-0", proto_ver=proto_ver, properties=props)

mid = 3
publish1p_packet = mosq_test.gen_publish("topic/1", qos=1, mid=mid, payload="test-message-1", proto_ver=proto_ver, properties=props)
puback1p_packet = mosq_test.gen_puback(mid, proto_ver=proto_ver)

mid = 4
publish2p_packet = mosq_test.gen_publish("topic/2", qos=2, mid=mid, payload="test-message-2", proto_ver=proto_ver, properties=props)
pubrec2p_packet = mosq_test.gen_pubrec(mid, proto_ver=proto_ver)
pubrel2p_packet = mosq_test.gen_pubrel(mid, proto_ver=proto_ver)
pubcomp2p_packet = mosq_test.gen_pubcomp(mid, proto_ver=proto_ver)

broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

try:
    sock = mosq_test.do_client_connect(connect1_packet, connack1_packet, timeout=20, port=port)

    # Trigger the plugin to send us some messages
    sock.send(publish_packet)

    mosq_test.expect_packet(sock, "publish0", publish0_packet)
    mosq_test.expect_packet(sock, "publish1", publish1_packet)
    sock.send(puback1_packet)

    mosq_test.expect_packet(sock, "publish2", publish2_packet)
    mosq_test.do_send_receive(sock, pubrec2_packet, pubrel2_packet, "pubrel1")
    sock.send(pubcomp2_packet)

    # And trigger the second set of messages, with properties
    sock.send(publish_packet)
    mosq_test.expect_packet(sock, "publish0p", publish0p_packet)
    mosq_test.expect_packet(sock, "publish1p", publish1p_packet)
    sock.send(puback1_packet)

    mosq_test.expect_packet(sock, "publish2p", publish2p_packet)
    mosq_test.do_send_receive(sock, pubrec2p_packet, pubrel2p_packet, "pubrel1p")
    sock.send(pubcomp2p_packet)

    mosq_test.do_ping(sock)

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
