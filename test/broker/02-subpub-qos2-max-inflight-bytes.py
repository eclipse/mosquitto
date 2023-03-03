#!/usr/bin/env python3

# Does the broker respect max_inflight_bytes?
# Also check whether the send quota is dealt with properly when both
# RECEIVE-MAXIMUM and max_inflight_bytes are set.
# MQTT v5

from mosq_test_helper import *

def helper(port):
    rc = 1
    connect_packet = mosq_test.gen_connect("subpub-qos2-recv-max1-helper", proto_ver=5)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    mid = 1
    publish_packet = mosq_test.gen_publish("subpub/qos2", qos=2, mid=mid, payload="message1", proto_ver=5)
    pubrec_packet = mosq_test.gen_pubrec(mid, proto_ver=5)
    pubrel_packet = mosq_test.gen_pubrel(mid, proto_ver=5)
    pubcomp_packet = mosq_test.gen_pubcomp(mid, proto_ver=5)

    mid = 2
    publish_packet2 = mosq_test.gen_publish("subpub/qos2", qos=2, mid=mid, payload="message2", proto_ver=5)
    pubrec_packet2 = mosq_test.gen_pubrec(mid, proto_ver=5)
    pubrel_packet2 = mosq_test.gen_pubrel(mid, proto_ver=5)
    pubcomp_packet2 = mosq_test.gen_pubcomp(mid, proto_ver=5)

    mid = 3
    publish_packet3 = mosq_test.gen_publish("subpub/qos2", qos=2, mid=mid, payload="message3", proto_ver=5)
    pubrec_packet3 = mosq_test.gen_pubrec(mid, proto_ver=5)
    pubrel_packet3 = mosq_test.gen_pubrel(mid, proto_ver=5)
    pubcomp_packet3 = mosq_test.gen_pubcomp(mid, proto_ver=5)


    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)

    mosq_test.do_send_receive(sock, publish_packet, pubrec_packet, "pubrec")
    mosq_test.do_send_receive(sock, pubrel_packet, pubcomp_packet, "pubcomp")

    mosq_test.do_send_receive(sock, publish_packet2, pubrec_packet2, "pubrec2")
    mosq_test.do_send_receive(sock, pubrel_packet2, pubcomp_packet2, "pubcomp2")

    mosq_test.do_send_receive(sock, publish_packet3, pubrec_packet3, "pubrec3")
    mosq_test.do_send_receive(sock, pubrel_packet3, pubcomp_packet3, "pubcomp3")
    sock.close()


def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")
        f.write("max_inflight_bytes 16\n")


def send_small(port):
    rc = 1
    connect_packet = mosq_test.gen_connect("subpub-qos2-test-helper")
    connack_packet = mosq_test.gen_connack(rc=0)

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)

    for i in range(0, 10):
        mid = 1+i
        publish_packet = mosq_test.gen_publish("subpub/qos2", qos=2, mid=mid, payload=str(i+1))
        pubrec_packet = mosq_test.gen_pubrec(mid)
        pubrel_packet = mosq_test.gen_pubrel(mid)
        pubcomp_packet = mosq_test.gen_pubcomp(mid)

        mosq_test.do_send_receive(sock, publish_packet, pubrec_packet, "pubrec")
        mosq_test.do_send_receive(sock, pubrel_packet, pubcomp_packet, "pubcomp")


def do_test(proto_ver):
    if proto_ver == 4:
        exit(0)

    rc = 1
    props = mqtt5_props.gen_uint16_prop(mqtt5_props.PROP_RECEIVE_MAXIMUM, 5)
    connect_packet = mosq_test.gen_connect("subpub-qos2-test", proto_ver=5, properties=props)
    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

    mid = 1
    subscribe_packet = mosq_test.gen_subscribe(mid, "subpub/qos2", 2, proto_ver=5)
    suback_packet = mosq_test.gen_suback(mid, 2, proto_ver=5)

    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port)
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port, use_conf=True)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=20, port=port)

        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

        # Repeat many times to stress the send quota
        mid = 0
        for i in range(0, 12):
            helper(port)
            #pub = subprocess.Popen(['./02-subpub-qos2-receive-maximum-helper.py', str(port)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            #if mosq_test.wait_for_subprocess(pub):
            #    print("pub not terminated")
            #    if rc == 0: rc=1
            #(stdo, stde) = pub.communicate()

            mid += 1
            publish_packet1 = mosq_test.gen_publish("subpub/qos2", qos=2, mid=mid, payload="message1", proto_ver=5)
            pubrec_packet1 = mosq_test.gen_pubrec(mid, proto_ver=5)
            pubrel_packet1 = mosq_test.gen_pubrel(mid, proto_ver=5)
            pubcomp_packet1 = mosq_test.gen_pubcomp(mid, proto_ver=5)

            mid += 1
            publish_packet2 = mosq_test.gen_publish("subpub/qos2", qos=2, mid=mid, payload="message2", proto_ver=5)
            pubrec_packet2 = mosq_test.gen_pubrec(mid, proto_ver=5)
            pubrel_packet2 = mosq_test.gen_pubrel(mid, proto_ver=5)
            pubcomp_packet2 = mosq_test.gen_pubcomp(mid, proto_ver=5)

            mid += 1
            publish_packet3 = mosq_test.gen_publish("subpub/qos2", qos=2, mid=mid, payload="message3", proto_ver=5)
            pubrec_packet3 = mosq_test.gen_pubrec(mid, proto_ver=5)
            pubrel_packet3 = mosq_test.gen_pubrel(mid, proto_ver=5)
            pubcomp_packet3 = mosq_test.gen_pubcomp(mid, proto_ver=5)


            mosq_test.expect_packet(sock, "publish1", publish_packet1)
            mosq_test.expect_packet(sock, "publish2", publish_packet2)
            mosq_test.do_send_receive(sock, pubrec_packet1, pubrel_packet1, "pubrel1")
            sock.send(pubcomp_packet1)

            mosq_test.expect_packet(sock, "publish3", publish_packet3)
            mosq_test.do_send_receive(sock, pubrec_packet2, pubrel_packet2, "pubrel2")
            sock.send(pubcomp_packet2)

            mosq_test.do_send_receive(sock, pubrec_packet3, pubrel_packet3, "pubrel3")
            sock.send(pubcomp_packet3)

        # send messages where count will exceed max_inflight_messages, but the
        # payload bytes won't exceed max_inflight_bytes
        send_small(port)

        mid += 1
        publish_packet1 = mosq_test.gen_publish("subpub/qos2", qos=2, mid=mid, payload="1", proto_ver=5)
        pubrec_packet1 = mosq_test.gen_pubrec(mid, proto_ver=5)
        pubrel_packet1 = mosq_test.gen_pubrel(mid, proto_ver=5)
        pubcomp_packet1 = mosq_test.gen_pubcomp(mid, proto_ver=5)

        mid += 1
        publish_packet2 = mosq_test.gen_publish("subpub/qos2", qos=2, mid=mid, payload="2", proto_ver=5)
        pubrec_packet2 = mosq_test.gen_pubrec(mid, proto_ver=5)
        pubrel_packet2 = mosq_test.gen_pubrel(mid, proto_ver=5)
        pubcomp_packet2 = mosq_test.gen_pubcomp(mid, proto_ver=5)

        mid += 1
        publish_packet3 = mosq_test.gen_publish("subpub/qos2", qos=2, mid=mid, payload="3", proto_ver=5)
        pubrec_packet3 = mosq_test.gen_pubrec(mid, proto_ver=5)
        pubrel_packet3 = mosq_test.gen_pubrel(mid, proto_ver=5)
        pubcomp_packet3 = mosq_test.gen_pubcomp(mid, proto_ver=5)

        mid += 1
        publish_packet4 = mosq_test.gen_publish("subpub/qos2", qos=2, mid=mid, payload="4", proto_ver=5)
        pubrec_packet4 = mosq_test.gen_pubrec(mid, proto_ver=5)
        pubrel_packet4 = mosq_test.gen_pubrel(mid, proto_ver=5)
        pubcomp_packet4 = mosq_test.gen_pubcomp(mid, proto_ver=5)

        mid += 1
        publish_packet5 = mosq_test.gen_publish("subpub/qos2", qos=2, mid=mid, payload="5", proto_ver=5)
        pubrec_packet5 = mosq_test.gen_pubrec(mid, proto_ver=5)
        pubrel_packet5 = mosq_test.gen_pubrel(mid, proto_ver=5)
        pubcomp_packet5 = mosq_test.gen_pubcomp(mid, proto_ver=5)

        mosq_test.expect_packet(sock, "publish1s", publish_packet1)
        mosq_test.expect_packet(sock, "publish2s", publish_packet2)
        mosq_test.expect_packet(sock, "publish3s", publish_packet3)
        mosq_test.expect_packet(sock, "publish4s", publish_packet4)
        mosq_test.expect_packet(sock, "publish5s", publish_packet5)
        
        mosq_test.do_send_receive(sock, pubrec_packet1, pubrel_packet1, "pubrel1s")
        mosq_test.do_send_receive(sock, pubrec_packet2, pubrel_packet2, "pubrel2s")
        mosq_test.do_send_receive(sock, pubrec_packet3, pubrel_packet3, "pubrel3s")
        mosq_test.do_send_receive(sock, pubrec_packet4, pubrel_packet4, "pubrel4s")
        mosq_test.do_send_receive(sock, pubrec_packet5, pubrel_packet5, "pubrel5s")

        rc = 0

        sock.close()
    except mosq_test.TestError:
        pass
    except Exception as e:
        print(e)
    finally:
        os.remove(conf_file)
        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1
        (stdo, stde) = broker.communicate()
        if rc:
            #print(stde.decode('utf-8'))
            print("proto_ver=%d" % (proto_ver))
            exit(rc)


do_test(proto_ver=5)
exit(0)
