#!/usr/bin/env python3

# Start two brokers one bridging forward to the second one (the bridge target).
# Once brokers are up and running we stop the bridge target broker, connect
# a publisher an publish a number of qos1 messages.
# Check all the messages should bestored in the persistence store.
# Afterwards start the bridge target broker, connect a client and
# add a matching subscription. Then start the bridging broker and check,
# if all messages are forwarded from the persistence store to bridge target
# and further to the subscriber.
# Finally check the persistence store contains zero messages.

from mosq_test_helper import *

persist_help = persist_module()

num_messages = 100
topic = "test/bridge-out"

port, bridge_target_port = mosq_test.get_port(2)

conf_file = os.path.basename(__file__).replace(".py", ".conf")
conf_file_bridge_target = os.path.basename(__file__).replace(
    ".py", "_bridge_target.conf"
)


def do_test(test_case_name: str, bridging_add_config: dict, target_add_config: dict):
    persist_help.write_config(
        conf_file, port, additional_config_entries=bridging_add_config
    )

    persist_help.write_config(
        conf_file_bridge_target,
        bridge_target_port,
        additional_config_entries=target_add_config,
    )

    rc = 1

    persist_help.init(port)
    persist_help.init(bridge_target_port)

    client_id = "persist-subscriber"

    qos = 1
    source_id = "persist-bridge-test-publisher"
    proto_ver = 4

    def gen_pub_packets(idx: int, mid_offset: int):
        payload = f"queued message {idx:3}"
        publish_packet = mosq_test.gen_publish(
            topic,
            mid=mid_offset + idx,
            qos=qos,
            payload=payload.encode("UTF-8"),
            proto_ver=proto_ver,
        )
        puback_packet = mosq_test.gen_puback(mid=mid_offset + idx, proto_ver=proto_ver)
        return publish_packet, puback_packet

    connect_packet = mosq_test.gen_connect(
        client_id, proto_ver=proto_ver, clean_session=False
    )
    connack_packet1 = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)
    connack_packet2 = mosq_test.gen_connack(rc=0, flags=1, proto_ver=proto_ver)

    mid = 1
    subscribe_packet = mosq_test.gen_subscribe(mid, topic, qos, proto_ver=proto_ver)
    suback_packet = mosq_test.gen_suback(mid, qos=qos, proto_ver=proto_ver)

    connect2_packet = mosq_test.gen_connect(source_id, proto_ver=proto_ver)
    connack2_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    num_messages = 100

    broker = None

    try:
        bridge_target_broker = mosq_test.start_broker(
            filename=conf_file_bridge_target, use_conf=True, port=bridge_target_port
        )

        # Connect to the bridge target broker and make a qos1 subscription
        sock_bridge_target = mosq_test.do_client_connect(
            connect_packet, connack_packet1, timeout=5, port=bridge_target_port
        )
        mosq_test.do_send_receive(
            sock_bridge_target,
            subscribe_packet,
            suback_packet,
            "suback from bridge target",
        )

        # Now start the broker with the bridge
        broker = mosq_test.start_broker(filename=conf_file, use_conf=True, port=port)

        # Connect and send a single message forwarded to the bridge target
        sock = mosq_test.do_client_connect(
            connect2_packet, connack2_packet, timeout=5, port=port
        )
        publish_packet, puback_packet = gen_pub_packets(0, mid_offset=3)
        mosq_test.do_send_receive(
            sock, publish_packet, puback_packet, "puback for first message"
        )

        # Wait until we have received the message from the bridge target
        publish_packet, puback_packet = gen_pub_packets(0, mid_offset=1)
        mosq_test.do_receive_send(
            sock_bridge_target, publish_packet, puback_packet, "first published message"
        )

        # Wait for a ping response to make sure the target broker has processed the PUBACK
        mosq_test.do_ping(sock_bridge_target)
        sock_bridge_target.close()

        # Make sure the bridging broker processes a ping, which means the PUBACK from the bridge target for the
        # first message was processed as well
        mosq_test.do_ping(sock)

        # Stop the bridge target broker
        (broker_terminate_rc, stde2) = mosq_test.terminate_broker(bridge_target_broker)
        bridge_target_broker = None

        # Publish messages
        for i in range(num_messages):
            publish_packet, puback_packet = gen_pub_packets(idx=i, mid_offset=10)
            mosq_test.do_send_receive(sock, publish_packet, puback_packet, "puback")
        sock.close()

        # Terminate the bridging broker
        (broker_terminate_rc, stde3) = mosq_test.terminate_broker(broker)
        broker = None

        persist_help.check_counts(
            port,
            clients=1,
            client_msgs_out=num_messages,
            base_msgs=num_messages,
            subscriptions=0,
        )

        # Check stored message
        for i in range(num_messages):
            payload = f"queued message {i:3}"
            payload_b = payload.encode("UTF-8")
            mid = 10 + i
            store_id = persist_help.check_base_msg(
                port,
                0,
                topic,
                payload_b,
                source_id,
                None,
                len(payload_b),
                mid,
                port,
                qos,
                retain=0,
                idx=i,
            )

            # Check client msg
            subscriber_mid = 4 + i
            cmsg_id = 2 + i
            persist_help.check_client_msg(
                port,
                "upstream-bridge",
                cmsg_id,
                store_id,
                0,
                persist_help.dir_out,
                subscriber_mid,
                qos,
                0,
                persist_help.ms_queued,
            )

        # Start the bridge target broker
        bridge_target_broker = mosq_test.start_broker(
            filename=conf_file_bridge_target, use_conf=True, port=bridge_target_port
        )

        # Reconnect to the bridge target broker
        sock = mosq_test.do_client_connect(
            connect_packet, connack_packet2, timeout=5, port=bridge_target_port
        )

        # Restart bridging broker
        broker = mosq_test.start_broker(filename=conf_file, use_conf=True, port=port)

        # Check, if all message got forwarded through the bridge
        for i in range(num_messages):
            publish_packet, puback_packet = gen_pub_packets(idx=i, mid_offset=1)
            mosq_test.do_receive_send(
                sock,
                publish_packet,
                puback_packet,
                f"Receive publish {i} after reconnect",
            )

        # Send ping and wait for the PINGRESP to make sure the broker has processed all sent puback
        mosq_test.do_ping(sock)
        sock.close()

        # Reconnect to the bridging broker and send ping to make sure the broker has process
        # PUBACK from bridge target before getting shut down
        sock = mosq_test.do_client_connect(
            connect2_packet, connack2_packet, timeout=5, port=port
        )
        mosq_test.do_ping(sock)
        sock.close()

        # Stop both brokers
        (broker_terminate_rc, stde2) = mosq_test.terminate_broker(bridge_target_broker)
        bridge_target_broker = None
        (broker_terminate_rc, stde) = mosq_test.terminate_broker(broker)
        broker = None

        persist_help.check_counts(
            port,
            clients=1,
            client_msgs_out=0,
            base_msgs=0,
            subscriptions=0,
        )

        rc = broker_terminate_rc
    finally:
        if broker is not None:
            broker.terminate()
            if mosq_test.wait_for_subprocess(broker):
                if rc == 0:
                    rc = 1
            (_, stde) = broker.communicate()
        if bridge_target_broker is not None:
            bridge_target_broker.terminate()
            if mosq_test.wait_for_subprocess(bridge_target_broker):
                if rc == 0:
                    rc = 1
            (_, stde2) = bridge_target_broker.communicate()
        os.remove(conf_file_bridge_target)
        os.remove(conf_file)
        rc += persist_help.cleanup(bridge_target_port)
        rc += persist_help.cleanup(port)

        print(f"{test_case_name}")
        if rc:
            if stde2 is not None:
                print("Bridge target brocker log:")
                print(stde2.decode("utf-8"))
            if stde3 is not None:
                print("Bridging brocker log (first run):")
                print(stde3.decode("utf-8"))
            if stde is not None:
                print("Bridging brocker log:")
                print(stde.decode("utf-8"))
        assert rc == 0, f"rc: {rc}"


in_bridge_config = {
    "connection": "in-bridge",
    "address": f"localhost:{port}",
    "local_clientid": "bridge-test",
    "remote_clientid": "upstream-bridge",
    "topic": f"{topic} in 2",
}

out_bridge_config = {
    "connection": "out-bridge",
    "address": f"localhost:{bridge_target_port}",
    "local_clientid": "upstream-bridge",
    "remote_clientid": "bridge-test",
    "topic": f"{topic} out 2",
}

memory_queue_config = {
    "max_queued_messages": num_messages,
    "max_inflight_messages": num_messages // 20,
}

do_test(
    "memory queue out bridge",
    bridging_add_config=memory_queue_config | out_bridge_config,
    target_add_config={},
)

# For a test of a push bridge we need to modify the start order
# of the brokers...
# do_test(
#     "memory queue in bridge",
#     bridging_add_config= memory_queue_config,
#     target_add_config=in_bridge_config
# )

exit(0)
