#!/usr/bin/env python3

# Test whether a bridge topics work correctly after reconnection.
# Important point here is that persistence is enabled.

from mosq_test_helper import *

mosq_test.require_features(["INC_BRIDGE_SUPPORT"])

def write_config(filename, port1, port2, protocol_version):
    with open(filename, 'w') as f:
        f.write("log_type all\n")
        f.write("listener %d\n" % (port2))
        f.write(f"plugin {mosq_paths.test_plugin('plugin_evt_persist_client_update')}\n")
        f.write("allow_anonymous true\n")
        f.write("persistent_client_expiration 1d\n")
        f.write("\n")
        f.write("connection connect_only_bridge\n")
        f.write("address localhost:%d\n" % (port1))
        f.write("topic bridge/# out\n")
        f.write("bridge_protocol_version %s\n" % (protocol_version))
        f.write("bridge_max_topic_alias 0\n")
        f.write("cleansession false\n")
        f.write("notification_topic bridge_state\n")
        f.write("restart_timeout 300\n")


def do_test(proto_ver):
    bridge_protocol = "mqttv311" if proto_ver == 4 else "mqttv50"

    (port1, port2) = mosq_test.get_port(2)
    conf_file = '06-bridge-remote-shutdown.conf'
    write_config(conf_file, port1, port2, bridge_protocol)

    rc = 1
    connect_packet = mqtt_packets.gen_connect("test-client", proto_ver=proto_ver)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)
    mid = 180
    subscribe_packet = mqtt_packets.gen_subscribe(mid, "#", 0, proto_ver=proto_ver)
    suback_packet = mqtt_packets.gen_suback(mid, 0, proto_ver=proto_ver)
    publish_packet = mqtt_packets.gen_publish("echo_topic", qos=0, payload="sample-message", proto_ver=proto_ver)
    bridge_up_packet = mqtt_packets.gen_publish("bridge_state", qos=0, payload="1", retain=1, proto_ver=proto_ver)
    bridge_down_packet = mqtt_packets.gen_publish("bridge_state", qos=0, payload="0", retain=0, proto_ver=proto_ver)
    
    remote_broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port1, use_conf=False)

    local_cmd = [mosq_paths.mosquitto, '-c', conf_file]
    local_broker = mosq_test.start_broker(cmd=local_cmd, filename=os.path.basename(__file__)+'_local1', use_conf=False, port=port2)    

    rc1 = None
    
    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port2)
        sock = mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        mosq_test.expect_packet(sock, "check for bridge up state", bridge_up_packet)

        rc1, stde1 = mosq_test.terminate_broker(remote_broker)
        
        mosq_test.expect_packet(sock, "wait for bridge down state", bridge_down_packet)
        # If we now get a message published to evt/persist/client/update instead of the expected echo
        # the bridge connection was most likely added to the expiry list
        sock = mosq_test.do_send_receive(sock, publish_packet, publish_packet)

        rc = 0

        sock.close()
    except mosq_test.TestError:
        
        pass
    finally:
        if rc1 is None:
            rc1, stde1 = mosq_test.terminate_broker(remote_broker)
        rc2, stde2 = mosq_test.terminate_broker(local_broker)
        if rc or rc1 or rc2:
            print(f"Remote broker first run rc={rc1}")
            print(stde1)

            print(f"Local broker rc={rc2}")
            print(stde2)
        try: 
            os.remove(conf_file)
        except OSError:
            pass
    return rc == 0

if do_test(proto_ver=4) and do_test(proto_ver=5):
    exit(0)

exit(1)

