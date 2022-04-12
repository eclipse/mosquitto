#!/usr/bin/env python3

# Check whether the broker disconnects a client nicely when they send a too large packet.

from mosq_test_helper import *

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")
        f.write("max_packet_size 40\n")

port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
write_config(conf_file, port)

rc = 1

connect_packet = mosq_test.gen_connect("12-max-packet-broker", proto_ver=5)
props = mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_MAXIMUM_PACKET_SIZE, 40)
connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5, properties=props)

publish_packet = mosq_test.gen_publish("12/max/packet/size/broker/test/topic", qos=0, payload="0123456789012345678901234567890", proto_ver=5)
disconnect_packet = mosq_test.gen_disconnect(reason_code=149, proto_ver=5)

broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port, use_conf=True)

try:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
    mosq_test.do_send_receive(sock, publish_packet, disconnect_packet, "disconnect")
    rc = 0
except mosq_test.TestError:
    pass
finally:
    broker.terminate()
    if mosq_test.wait_for_subprocess(broker):
        print("broker not terminated")
        if rc == 0: rc=1
    os.remove(conf_file)
    (stdo, stde) = broker.communicate()
    if rc:
        print(stde.decode('utf-8'))

exit(rc)

