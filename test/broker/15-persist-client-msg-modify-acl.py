#!/usr/bin/env python3

# Connect a client, add a subscription, disconnect, send a message with a
# different client, restore, reconnect, check it is received.

from mosq_test_helper import *

persist_help = persist_module()

port = mosq_test.get_port()

num_messages = 100


def do_test(test_case_name: str, additional_config_entries: dict):
    conf_file = os.path.basename(__file__).replace(".py", ".conf")
    acl_file = os.path.basename(__file__).replace(".py", ".acl")
    persist_help.write_config(
        conf_file,
        port,
        additional_config_entries={"acl_file": f"{acl_file}"}
        | additional_config_entries,
    )
    persist_help.init(port)

    client_id = "test-change-acl-subscriber"
    username = "test-acl-change"

    qos = 1
    topic = "client-msg/test"
    source_id = "test-change-acl-publisher"
    proto_ver = 4

    connect_packet = mosq_test.gen_connect(
        client_id, username=username, proto_ver=proto_ver, clean_session=False
    )
    connack_packet1 = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)
    connack_packet2 = mosq_test.gen_connack(rc=0, flags=1, proto_ver=proto_ver)

    mid = 1
    subscribe_packet = mosq_test.gen_subscribe(mid, topic, qos, proto_ver=proto_ver)
    suback_packet = mosq_test.gen_suback(mid, qos=qos, proto_ver=proto_ver)

    connect2_packet = mosq_test.gen_connect(
        source_id, proto_ver=proto_ver, username=username
    )
    connack2_packet = mosq_test.gen_connack(rc=0, proto_ver=proto_ver)

    with open(acl_file, "w") as f:
        f.write(f"user {username}\n")
        f.write(f"pattern readwrite {topic}\n")
    os.chmod(f"{acl_file}", 0o644)

    rc = 1

    broker = mosq_test.start_broker(filename=conf_file, use_conf=True, port=port)

    con = None
    try:
        sock = mosq_test.do_client_connect(
            connect_packet, connack_packet1, timeout=5, port=port
        )
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")
        sock.close()

        sock = mosq_test.do_client_connect(
            connect2_packet, connack2_packet, timeout=5, port=port
        )
        for i in range(num_messages):
            payload = f"queued message {i:3}"
            mid = 10 + i
            publish_packet = mosq_test.gen_publish(
                topic,
                mid=mid,
                qos=qos,
                payload=payload.encode("UTF-8"),
                proto_ver=proto_ver,
            )
            puback_packet = mosq_test.gen_puback(mid=mid, proto_ver=proto_ver)
            mosq_test.do_send_receive(sock, publish_packet, puback_packet, "puback")
        sock.close()

        # Terminate the broker
        (broker_terminate_rc, stde) = mosq_test.terminate_broker(broker)
        broker = None

        persist_help.check_counts(
            port,
            clients=1,
            client_msgs_out=num_messages,
            base_msgs=num_messages,
            subscriptions=1,
        )

        # Check client
        persist_help.check_client(
            port,
            client_id,
            username=username,
            will_delay_time=0,
            session_expiry_time=0,
            listener_port=port,
            max_packet_size=0,
            max_qos=2,
            retain_available=1,
            session_expiry_interval=4294967295,
            will_delay_interval=0,
        )

        # Check subscription
        persist_help.check_subscription(port, client_id, topic, qos, 0)

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
                username,
                len(payload_b),
                mid,
                port,
                qos,
                retain=0,
                idx=i,
            )

            # Check client msg
            subscriber_mid = 1 + i
            cmsg_id = 1 + i
            persist_help.check_client_msg(
                port,
                client_id,
                cmsg_id,
                store_id,
                0,
                persist_help.dir_out,
                subscriber_mid,
                qos,
                0,
                persist_help.ms_queued,
            )

        # Remove any permission for the test topic and the test user
        with open(acl_file, "w") as f:
            f.write(f"user {username}\n")
            f.write(f"pattern deny {topic}\n")
        os.chmod(f"{acl_file}", 0o644)

        # Restart broker
        broker = mosq_test.start_broker(filename=conf_file, use_conf=True, port=port)

        # Connect client again, it should have a session, but all queued messages should be dropped
        sock = mosq_test.do_client_connect(
            connect_packet, connack_packet2, timeout=5, port=port
        )

        # Send ping and wait for the PINGRESP to make sure the broker will not send a queued message instead
        mosq_test.do_ping(sock)
        sock.close()

        (broker_terminate_rc, stde) = mosq_test.terminate_broker(broker)
        broker = None

        persist_help.check_counts(
            port,
            clients=1,
            client_msgs_out=0,
            base_msgs=0,
            subscriptions=1,
        )

        rc = broker_terminate_rc
    finally:
        if broker is not None:
            broker.terminate()
            if mosq_test.wait_for_subprocess(broker):
                if rc == 0:
                    rc = 1
            (_, stde) = broker.communicate()
        os.remove(acl_file)
        os.remove(conf_file)
        rc += persist_help.cleanup(port)

        print(f"{test_case_name}")
        if rc:
            print(stde.decode("utf-8"))
        assert rc == 0, f"rc: {rc}"


do_test(
    "memory queue",
    additional_config_entries={
        "max_queued_messages": num_messages,
        "max_inflight_messages": num_messages // 20,
    },
)
