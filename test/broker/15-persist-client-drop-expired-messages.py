#!/usr/bin/env python3

# Connect a client, add a subscription, disconnect, send a message with a
# different client, restore, reconnect, check it is received.

from mosq_test_helper import *
from persist_module_helper import *

persist_help = persist_module()

port = mosq_test.get_port()

num_messages = 100

proto_ver = 5
qos = 1
topic = "test-expired-msgs"
username = "test-message-expiry"

subscriber_id = "test-subscriber"
second_subscriber_id = "second-subscriber"
publisher_id = "test-publisher"


def do_test(
    test_case_name: str,
    additional_config_entries: dict,
    resubscribe: bool,
    num_messages_two_subscribers: int = 0,
    num_retain_messages : int = 0,
):
    print(
        f"{test_case_name}, resubscribe = {resubscribe}, two_subscribers = {'True' if num_messages_two_subscribers > 0 else 'False'}, num_retain_messages = {num_retain_messages} "
    )

    conf_file = os.path.basename(__file__).replace(".py", f"_{port}.conf")
    persist_help.write_config(
        conf_file,
        port,
        additional_config_entries=additional_config_entries,
    )
    persist_help.init(port)

    connect2_packet = mosq_test.gen_connect(
        publisher_id, username=username, proto_ver=proto_ver
    )

    rc = 1

    broker = mosq_test.start_broker(filename=conf_file, use_conf=True, port=port)

    con = None
    try:
        msg_counts = {subscriber_id: num_messages}

        connect_client(
            port,
            subscriber_id,
            username,
            proto_ver,
            session_expiry=60,
            subscribe_topic=topic,
        ).close()

        publisher_sock = connect_client(
            port, publisher_id, username, proto_ver, session_expiry=0
        )
        publish_messages(
            publisher_sock,
            proto_ver,
            topic,
            0,
            num_messages - num_messages_two_subscribers,
            message_expiry=60,
            retain_end=num_retain_messages,
        )

        if num_messages_two_subscribers > 0:
            msg_counts[second_subscriber_id] = num_messages_two_subscribers
            connect_client(
                port,
                second_subscriber_id,
                username,
                proto_ver,
                session_expiry=60,
                subscribe_topic=topic,
            ).close()
            publish_messages(
                publisher_sock,
                proto_ver,
                topic,
                num_messages - num_messages_two_subscribers,
                num_messages,
                message_expiry=60,
                retain_end=num_retain_messages,
            )
        publisher_sock.close()

        # Terminate the broker
        (broker_terminate_rc, stde) = mosq_test.terminate_broker(broker)
        broker = None

        check_db(
            persist_help,
            port,
            username,
            subscription_topic=topic,
            client_msg_counts=msg_counts,
            publisher_id=publisher_id,
            num_published_msgs=num_messages,
            retain_end = num_retain_messages,
            message_expiry=60,
        )

        # Put session expiry_time into the past
        assert persist_help.modify_base_msgs(port, sub_expiry_time=120) == num_messages

        # Restart broker
        broker = mosq_test.start_broker(filename=conf_file, use_conf=True, port=port)

        # Reconnect client(s), it should have a session, but all queued messages should be dropped
        for client_id in msg_counts.keys():
            subscriber_sock = connect_client(
                port,
                client_id,
                username,
                proto_ver,
                session_expiry=60,
                session_present=True,
                subscribe_topic=topic if resubscribe else None,
            )
        # Send ping and wait for the PINGRESP to make sure the broker will not send a queued message instead
        mosq_test.do_ping(subscriber_sock)
        subscriber_sock.close()

        (broker_terminate_rc, stde) = mosq_test.terminate_broker(broker)
        broker = None

        for client_id in msg_counts.keys():
            # None for subscriber with subscriber_id means no subscription
            msg_counts[client_id] = 0
        check_db(
            persist_help,
            port,
            username,
            subscription_topic=topic,
            client_msg_counts=msg_counts,
            publisher_id=publisher_id,
            num_published_msgs=num_messages,
            retain_end = 0,
        )

        rc = broker_terminate_rc
    finally:
        if broker is not None:
            broker.terminate()
            if mosq_test.wait_for_subprocess(broker):
                if rc == 0:
                    rc = 1
            (_, stde) = broker.communicate()
        os.remove(conf_file)
        rc += persist_help.cleanup(port)

        if rc:
            print(stde.decode("utf-8"))
        assert rc == 0, f"rc: {rc}"


memory_queue_config = {
    "log_type": "all",
    "max_queued_messages": num_messages,
}

do_test(
    "memory queue",
    additional_config_entries=memory_queue_config,
    resubscribe=False,
)
do_test(
    "memory queue",
    additional_config_entries=memory_queue_config,
    resubscribe=True,
)
do_test(
    "memory queue",
    additional_config_entries=memory_queue_config,
    resubscribe=False,
    num_messages_two_subscribers=30,
)
do_test(
    "memory queue",
    additional_config_entries=memory_queue_config,
    resubscribe=False,
    num_retain_messages=40,
)
