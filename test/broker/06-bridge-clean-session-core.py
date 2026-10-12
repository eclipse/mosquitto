#!/usr/bin/env python3
# Test whether a broker handles cleansession and local_cleansession correctly on bridges
#
# Test cases (with settings for broker A (edge). The settings on broker B (core)
# are irrelevant, though you'll need persistence enabled to test, unless you
# can simulate network interruptions.
# Similarly, you'll need persistence on A, _purely_ to simplify the testing with a client
# t# | LCS | CS | queued from (expected)
#               | A->B | B->A
#  1 |  -(t| t  |  no  | no
#  2 |  -(f| f  |  yes | yes
#  3 |  t  | t  |  no  | no  (as per #1)
#  4 |  t  | f  |  no  | yes
#  5 |  f  | t  |  yes | no
#  6 |  f  | f  |  yes | yes (as per #2)
#
# Test setup is two (real) brokers, so that messages can be published and subscribed in both
# directions, with two test clients, one at each end.

# Disable on Travis for now, too unreliable
from mosq_test_helper import *
from collections import namedtuple

# Normally we don't want tests to spew debug, but if you're working on a test, it's useful
VERBOSE_TEST=False
def tprint(*args, **kwargs):
    if VERBOSE_TEST:
        print(" ".join(map(str,args)), **kwargs)

# this is our "A" broker
def write_config_edge(filename, persistence_file, remote_port, listen_port, protocol_version, cs=False, lcs=None):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (listen_port))
        f.write("allow_anonymous true\n")
        f.write("\n")
        f.write("persistence true\n")
        f.write("persistence_file %s\n" % (persistence_file))
        f.write("\n")
        f.write("connection bridge_sample\n")
        f.write("local_clientid id_local\n")
        f.write("remote_clientid id_remote\n")
        f.write("address localhost:%d\n" % (remote_port))
        f.write("topic br_out/# out 1\n")
        f.write("topic br_in/# in 1\n")
        # We need to ensure connections break fast enough to keep test times sane
        f.write("keepalive_interval 5\n")
        f.write("restart_timeout 2\n")
        f.write("cleansession %s\n" % ("true" if cs else "false"))
        # Ensure defaults are tested
        if lcs is not None:
            f.write("local_cleansession %s\n" % ("true" if lcs else "false"))
        f.write("bridge_protocol_version %s\n" % (protocol_version))
        f.write("bridge_max_topic_alias 0\n")


# this is our "B" broker
def write_config_core(filename, listen_port, persistence_file):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (listen_port))
        f.write("allow_anonymous true\n")
        f.write("\n")
        f.write("persistence true\n")
        f.write("persistence_file %s\n" % (persistence_file))


def wait_for_bridge_to_connect(port, clientid):
    conn = mqtt_packets.gen_connect("helper", clean_session=True)
    connack = mqtt_packets.gen_connack(rc=0)

    sock = mosq_test.do_client_connect(conn, connack, port=port)
    sub = mqtt_packets.gen_subscribe(1, f'$SYS/broker/connection/{clientid}/state', 0)
    suback = mqtt_packets.gen_suback(1, 0)
    mosq_test.do_send_receive(sock, sub, suback)
    pub_r = mqtt_packets.gen_publish(topic=f"$SYS/broker/connection/{clientid}/state", payload="1", qos=0, retain=True)
    pub_nr = mqtt_packets.gen_publish(topic=f"$SYS/broker/connection/{clientid}/state", payload="1", qos=0)
    pub_rec = sock.recv(len(pub_r))
    if pub_rec != pub_r and pub_rec != pub_nr:
        raise ValueError(mosq_test.to_string(pub_rec))
    sock.close()


def do_test(proto_ver, cs, lcs=None):
    tprint("Running test with cs:%s, lcs: %s and proto: %d" % (cs, lcs, proto_ver))
    if proto_ver == 4:
        bridge_protocol = "mqttv311"
    else:
        bridge_protocol = "mqttv50"

    # Match default behaviour of broker
    expect_queued_ab = True
    expect_queued_ba = True
    if lcs is None:
        lcs = cs
    if lcs:
        expect_queued_ab = False
    if cs:
        expect_queued_ba = False


    (port_a_listen, port_b_listen) = mosq_test.get_port(2)
    conf_file_a = os.path.basename(__file__).replace('.py', '%d_a_edge.conf'%(port_a_listen))
    persistence_file_a = os.path.basename(__file__).replace('.py', '%d_a_edge.db'%(port_a_listen))
    write_config_edge(conf_file_a, persistence_file_a, port_b_listen, port_a_listen, bridge_protocol, cs=cs, lcs=lcs)

    conf_file_b = os.path.basename(__file__).replace('.py', '%d_b_core.conf'%(port_b_listen))
    persistence_file_b = os.path.basename(__file__).replace('.py', '%d_b_core.db'%(port_b_listen))
    write_config_core(conf_file_b, port_b_listen, persistence_file_b)

    AckedPair = namedtuple("AckedPair", "p ack")

    def make_conn(client_tag, proto, cs, session_present=False):
        client_id = socket.gethostname() + "." + client_tag
        conn = mqtt_packets.gen_connect(client_id, clean_session=cs, proto_ver=proto, session_expiry=0 if cs else 5000)
        connack = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver, flags=1 if session_present else 0)
        return AckedPair(conn, connack)


    def make_sub(topic, mid, qos, proto):
        if proto_ver == 5:
            opts = mqtt5_opts.MQTT_SUB_OPT_NO_LOCAL | mqtt5_opts.MQTT_SUB_OPT_RETAIN_AS_PUBLISHED
        else:
            opts = 0
        sub = mqtt_packets.gen_subscribe(mid, topic, qos | opts, proto_ver=proto)
        suback = mqtt_packets.gen_suback(mid, qos, proto_ver=proto)
        return AckedPair(sub, suback)


    def make_pub(topic, mid, proto, qos=1, payload_tag="message", rc=-1):
        # Using the mid automatically makes it hard to verify messages that might have been retransmitted.
        # encourage users to put sequence numbers in topics instead....
        pub = mqtt_packets.gen_publish(topic, mid=mid, qos=qos, retain=False, payload=payload_tag + "-from-" + topic, proto_ver=proto)
        puback = mqtt_packets.gen_puback(mid, proto_ver=proto, reason_code=rc)
        return AckedPair(pub, puback)

    # Clients are testing messages in both directions, they need to be durable
    conn_a = make_conn("client_a_edge", proto_ver, False)
    conn_b = make_conn("client_b_core", proto_ver, False)
    # We expect session present when we reconnect
    reconn_a = make_conn("client_a_edge", proto_ver, False, session_present=True)
    reconn_b = make_conn("client_b_core", proto_ver, False, session_present=True)

    # remember, mids are from each broker's point of view, not the "world"
    sub_a = make_sub("br_in/#", qos=1, mid=1, proto=proto_ver)
    sub_b = make_sub("br_out/#", qos=1, mid=1, proto=proto_ver)

    pub_a1 = make_pub("br_out/test-queued1", mid=1, proto=proto_ver)
    pub_a2 = make_pub("br_out/test-queued2", mid=2, proto=proto_ver)
    pub_a3 = make_pub("br_out/test-queued3", mid=3, proto=proto_ver)
    pub_a3r = make_pub("br_out/test-queued3", mid=2, proto=proto_ver) # without queueing, there is no a2

    pub_b1 = make_pub("br_in/test-queued1", mid=1, proto=proto_ver)
    pub_b2 = make_pub("br_in/test-queued2", mid=2, proto=proto_ver)
    pub_b3 = make_pub("br_in/test-queued3", mid=3, proto=proto_ver)
    pub_b3r = make_pub("br_in/test-queued3", mid=2, proto=proto_ver) # without queueing, there is no b2

    success = False
    broker_termination_success = True
    stde_a1 = stde_b1 = None
    try:
        # b must start first, as it's the destination of a
        broker_b = mosq_test.start_broker(filename=conf_file_b, port=port_b_listen, use_conf=True)
        broker_a = mosq_test.start_broker(filename=conf_file_a, port=port_a_listen, use_conf=True)

        client_a = mosq_test.do_client_connect(conn_a.p, conn_a.ack, port=port_a_listen)
        mosq_test.do_send_receive(client_a, sub_a.p, sub_a.ack, "suback_a")

        client_b = mosq_test.do_client_connect(conn_b.p, conn_b.ack, port=port_b_listen)
        mosq_test.do_send_receive(client_b, sub_b.p, sub_b.ack, "suback_b")

        mosq_test.do_send_receive(client_a, pub_a1.p, pub_a1.ack, "puback_a1")
        mosq_test.do_receive_send(client_b, pub_a1.p, pub_a1.ack, "a->b1 (b-side)")

        mosq_test.do_send_receive(client_b, pub_b1.p, pub_b1.ack, "puback_b1")
        mosq_test.do_receive_send(client_a, pub_b1.p, pub_b1.ack, "b->a1 (a-side)")

        tprint("Normal bi-dir bridging works. continuing")

        mosq_test.terminate_broker(broker_b)
        if mosq_test.wait_for_subprocess(broker_b):
            print("broker_b not terminated")
            broker_termination_success = False
        stde_b1 = mosq_test.broker_log(broker_b)

        # as we're _terminating_ the connections should close ~straight away
        tprint("terminated B", time.time())
        time.sleep(0.5)

        # should be queued (or not)
        mosq_test.do_send_receive(client_a, pub_a2.p, pub_a2.ack, "puback_a2")

        broker_b = mosq_test.start_broker(filename=conf_file_b, port=port_b_listen, use_conf=True)
        # client b needs to reconnect now!

        client_b = mosq_test.do_client_connect(reconn_b.p, reconn_b.ack, port=port_b_listen)
        tprint("client b reconnected after restarting broker b at ", time.time())
        wait_for_bridge_to_connect(port_b_listen, "id_remote")

        # should go through
        tprint("(B should be alive again now!) sending (after reconn!) a3 at ", time.time())
        mosq_test.do_send_receive(client_a, pub_a3.p, pub_a3.ack, "puback_a3")


        if expect_queued_ab:
            tprint("1.expecting a->b queueing")
            mosq_test.do_receive_send(client_b, pub_a2.p, pub_a2.ack, "a->b_2")
            mosq_test.do_receive_send(client_b, pub_a3.p, pub_a3.ack, "a->b_3")
        else:
            tprint("not expecting a->b queueing")
            mosq_test.do_receive_send(client_b, pub_a3r.p, pub_a3r.ack, "a->b_3(r)")

        tprint("Stage 1 complete, repeating in other direction")

        # ok, now repeat in the other direction...
        mosq_test.terminate_broker(broker_a)
        if mosq_test.wait_for_subprocess(broker_a):
            print("broker_a not terminated")
            broker_termination_success = False
        stde_a1 = mosq_test.broker_log(broker_a)
        time.sleep(0.5)

        mosq_test.do_send_receive(client_b, pub_b2.p, pub_b2.ack, "puback_b2")

        broker_a = mosq_test.start_broker(filename=conf_file_a, port=port_a_listen, use_conf=True)
        # client a needs to reconnect now!
        client_a = mosq_test.do_client_connect(reconn_a.p, reconn_a.ack, port=port_a_listen)
        tprint("client A reconnected after restarting broker A at ", time.time())
        wait_for_bridge_to_connect(port_a_listen, "id_remote")

        # should go through
        client_b.send(pub_b3.p)

        if expect_queued_ba:
            tprint("2.expecting b->a queueueing")
            mosq_test.do_receive_send(client_a, pub_b2.p, pub_b2.ack, "b->a_2")
            mosq_test.do_receive_send(client_a, pub_b3.p, pub_b3.ack, "b->a_3")
        else:
            tprint("not expecting message b->a_2")
            mosq_test.do_receive_send(client_a, pub_b3r.p, pub_b3r.ack, "b->a_3(r)")

        success = broker_termination_success

    except Exception as e:
        print(e)
    except mosq_test.TestError:
        pass
    finally:
        os.remove(conf_file_a)
        os.remove(conf_file_b)
        mosq_test.terminate_broker(broker_a)
        mosq_test.terminate_broker(broker_b)
        if mosq_test.wait_for_subprocess(broker_a):
            print("broker_a not terminated")
            success = False
        if mosq_test.wait_for_subprocess(broker_b):
            print("broker_b not terminated")
            success = False
        stde_a = mosq_test.broker_log(broker_a)
        stde_b = mosq_test.broker_log(broker_b)
        # Must be after terminating!
        try:
            os.remove(persistence_file_a)
        except FileNotFoundError:
            print("persistence file a didn't exist, skipping remove")
        try:
            os.remove(persistence_file_b)
        except FileNotFoundError:
            print("persistence file b didn't exist, skipping remove")
        if not success:
            print("Test failed, dumping broker A logs: ")
            if stde_a1:
                print(stde_a1)
            print(stde_a)
            print("Test failed, dumping broker B logs: ")
            if stde_b1:
                print(stde_b1)
            print(stde_b)
            exit(1)

if sys.argv[3] == "True":
    cs = True
elif sys.argv[3] == "False":
    cs = False
else:
    raise ValueError("cs")

if sys.argv[4] == "True":
    lcs = True
elif sys.argv[4] == "False":
    lcs = False
elif sys.argv[4] == "None":
    lcs = None
else:
    raise ValueError("lcs")

do_test(proto_ver=4, cs=cs, lcs=lcs)
# FIXME - v5 clean session bridging doesn't work: see
# https://github.com/eclipse-mosquitto/mosquitto/issues/1632
#do_test(proto_ver=5, cs=cs, lcs=lcs)

exit(0)
