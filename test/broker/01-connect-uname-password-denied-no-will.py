#!/usr/bin/env python3

# Test whether a connection is denied if it provides a correct username but
# incorrect password. The client has a will, but it should not be sent. Check that.

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker

mosq_test.require_features(["WITH_TLS"])

def write_pwfile(filename):
    with open(filename, 'w') as f:
        # Username user, password password
        f.write('user:$6$vZY4TS+/HBxHw38S$vvjVFECzb8dyuu/mruD2QKTfdFn0WmKxbc+1TsdB0L8EdHk3v9JRmfjHd56+VaTnUcSZOZ/hzkdvWCtxlX7AUQ==\n')


def do_test(proto_ver):
    pw_file = os.path.basename(__file__).replace('.py', '.pwfile')
    write_pwfile(pw_file)
    connect1_packet = mqtt_packets.gen_connect("connect-uname-pwd-test", username="user", password="password", will_topic="will/test", will_payload=b"will msg", proto_ver=proto_ver)
    connack1_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    mid = 1
    subscribe_packet = mqtt_packets.gen_subscribe(mid, topic="will/test", qos=0, proto_ver=proto_ver)
    suback_packet = mqtt_packets.gen_suback(mid, 0, proto_ver=proto_ver)

    connect2_packet = mqtt_packets.gen_connect("connect-uname-pwd-test", username="user", password="password9", proto_ver=proto_ver)
    if proto_ver == 5:
        connack2_packet = mqtt_packets.gen_connack(rc=mqtt5_rc.NOT_AUTHORIZED, proto_ver=proto_ver, properties=None)
    else:
        connack2_packet = mqtt_packets.gen_connack(rc=5, proto_ver=proto_ver)

    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port) ],
        allow_anonymous=False,
        password_file=os.path.basename(__file__).replace('.py', '.pwfile')
    )
    broker = MosquittoBroker(config=broker_config)
    broker.add_extra_file(pw_file)
    with broker:
        sock1 = mosq_test.do_client_connect(connect1_packet, connack1_packet, port=port)
        mosq_test.do_send_receive(sock1, subscribe_packet, suback_packet)

        sock2 = mosq_test.do_client_connect(connect2_packet, connack2_packet, port=port)
        sock2.close()

        # If we receive a will here, this is an error
        mosq_test.do_ping(sock1)
        sock1.close()


do_test(proto_ver=4)
do_test(proto_ver=5)
