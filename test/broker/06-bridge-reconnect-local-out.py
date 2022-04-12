#!/usr/bin/env python3

# Test whether a bridge topics work correctly after reconnection.
# Important point here is that persistence is enabled.

from mosq_test_helper import *

def write_config(filename, port1, port2, protocol_version):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port2))
        f.write("allow_anonymous true\n")
        f.write("\n")
        f.write("persistence true\n")
        f.write("persistence_file mosquitto-%d.db" % (port1))
        f.write("\n")
        f.write("connection bridge_sample\n")
        f.write("address 127.0.0.1:%d\n" % (port1))
        f.write("topic bridge/# out\n")
        f.write("bridge_protocol_version %s\n" % (protocol_version))
        f.write("bridge_max_topic_alias 0\n")


def do_test(proto_ver):
    if proto_ver == 4:
        bridge_protocol = "mqttv311"
        proto_ver_connect = 128+4
    else:
        bridge_protocol = "mqttv50"
        proto_ver_connect = 5

    (port1, port2) = mosq_test.get_port(2)
    conf_file = '06-bridge-reconnect-local-out.conf'
    write_config(conf_file, port1, port2, bridge_protocol)

    rc = 1
    connect_packet = mosq_test.gen_connect("bridge-reconnect-test", proto_ver=proto_ver_connect)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    mid = 180
    subscribe_packet = mosq_test.gen_subscribe(mid, "bridge/#", 0, proto_ver=proto_ver)
    suback_packet = mosq_test.gen_suback(mid, 0, proto_ver=proto_ver)
    publish_packet = mosq_test.gen_publish("bridge/reconnect", qos=0, payload="bridge-reconnect-message", proto_ver=proto_ver)

    try:
        os.remove('mosquitto-%d.db' % (port1))
    except OSError:
        pass

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port1, use_conf=False)

    local_cmd = ['../../src/mosquitto', '-c', '06-bridge-reconnect-local-out.conf']
    local_broker = mosq_test.start_broker(cmd=local_cmd, filename=os.path.basename(__file__)+'_local1', use_conf=False, port=port2)
    if os.environ.get('MOSQ_USE_VALGRIND') is not None:
        time.sleep(5)
    else:
        time.sleep(0.5)
    local_broker.terminate()
    if mosq_test.wait_for_subprocess(local_broker):
        print("local_broker not terminated")
        if rc == 0: rc=1
    if os.environ.get('MOSQ_USE_VALGRIND') is not None:
        time.sleep(5)
    else:
        time.sleep(0.5)
    local_broker = mosq_test.start_broker(cmd=local_cmd, filename=os.path.basename(__file__)+'_local2', port=port2)
    if os.environ.get('MOSQ_USE_VALGRIND') is not None:
        time.sleep(5)
    else:
        time.sleep(0.5)

    pub = None
    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port1)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        # Helper
        helper_connect_packet = mosq_test.gen_connect("test-helper", proto_ver=proto_ver)
        helper_connack_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)
        helper_publish_packet = mosq_test.gen_publish("bridge/reconnect", qos=1, mid=1, payload="bridge-reconnect-message", proto_ver=proto_ver)
        helper_puback_packet = mosq_test.gen_puback(mid=1, proto_ver=proto_ver)
        helper_disconnect_packet = mosq_test.gen_disconnect(proto_ver=proto_ver)
        helper_sock = mosq_test.do_client_connect(helper_connect_packet, helper_connack_packet, port=port2, connack_error="helper connack")
        mosq_test.do_send_receive(helper_sock, helper_publish_packet, helper_puback_packet, "puback")
        helper_sock.send(helper_disconnect_packet)
        helper_sock.close()
        # End of helper

        # Should have now received a publish command
        mosq_test.expect_packet(sock, "publish", publish_packet)
        rc = 0

        sock.close()
    except mosq_test.TestError:
        pass
    finally:
        os.remove(conf_file)
        time.sleep(1)
        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1
        (stdo, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
        local_broker.terminate()
        if mosq_test.wait_for_subprocess(local_broker):
            print("local_broker not terminated")
            if rc == 0: rc=1
        try:
            os.remove('mosquitto-%d.db' % (port1))
        except OSError:
            pass

        if rc:
            (stdo, stde) = local_broker.communicate()
            print(stde.decode('utf-8'))
            if pub:
                (stdo, stde) = pub.communicate()
                print(stdo.decode('utf-8'))
            exit(rc)


do_test(proto_ver=4)
do_test(proto_ver=5)

exit(0)

