#!/usr/bin/env python3

import socket
import mosq_test
import mqtt5_props

from typing import Optional
from types import ModuleType


def connect_client(
    port: int,
    client_id: str,
    username: str,
    proto_ver: int,
    session_expiry: int,
    session_present: bool = False,
    subscribe_topic: Optional[str] = None,
    qos: int = 1,
):
    connect_packet = mosq_test.gen_connect(
        client_id=client_id,
        username=username,
        proto_ver=proto_ver,
        clean_session=False,
        session_expiry=session_expiry,
    )
    connack_packet = mosq_test.gen_connack(
        rc=0, proto_ver=proto_ver, flags=1 if session_present else 0
    )
    sock = mosq_test.do_client_connect(
        connect_packet, connack_packet, timeout=5, port=port
    )
    if subscribe_topic is not None:
        mid = 1
        subscribe_packet = mosq_test.gen_subscribe(
            mid, subscribe_topic, qos, proto_ver=proto_ver
        )
        suback_packet = mosq_test.gen_suback(mid, qos=qos, proto_ver=proto_ver)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")
    return sock


def publish_messages(
    sock: socket,
    proto_ver: int,
    topic: str,
    start: int,
    end: int,
    retain_end=0,
    message_expiry: int = 0,
    qos: int = 1,
):
    for i in range(start, end):
        payload = f"queued message {i:3}"
        mid = 10 + i
        props = (
            mqtt5_props.gen_uint32_prop(
                mqtt5_props.PROP_MESSAGE_EXPIRY_INTERVAL, message_expiry
            )
            if message_expiry > 0
            else b""
        )
        publish_packet = mosq_test.gen_publish(
            topic,
            mid=mid,
            qos=qos,
            payload=payload.encode("UTF-8"),
            retain = True if i < retain_end else False,
            proto_ver=proto_ver,
            properties=props,
        )
        puback_packet = mosq_test.gen_puback(mid=mid, proto_ver=proto_ver)
        mosq_test.do_send_receive(sock, publish_packet, puback_packet, "puback")


def check_db(
    persist_help: ModuleType,
    port: int,
    username: str,
    subscription_topic: str,
    client_msg_counts: dict[str, int],
    publisher_id: str,
    num_published_msgs: int,
    retain_end: int,
    message_expiry: int = 0,
    qos: int = 1,
):
    count_list = [v for v in client_msg_counts.values() if v is not None] + [0]
    num_base_msgs = max(count_list)
    num_subscriptions = sum(1 for c in client_msg_counts.values() if c is not None)
    num_client_msgs_out = sum(count_list)
    persist_help.check_counts(
        port,
        clients=len(client_msg_counts),
        client_msgs_out=num_client_msgs_out,
        base_msgs=num_base_msgs if num_base_msgs > 0 or retain_end == 0 else 1,
        retain_msgs=1 if retain_end > 0 else 0,
        subscriptions=num_subscriptions,
    )

    # Check client
    for client_id, num_messages_for_client in client_msg_counts.items():
        persist_help.check_client(
            port,
            client_id,
            username=username,
            will_delay_time=0,
            session_expiry_time=60,
            listener_port=None,  # persist-lmdb reset listener port to 0 on disconnect
            max_packet_size=0,
            max_qos=2,
            retain_available=1,
            session_expiry_interval=60,
            will_delay_interval=0,
        )
        # Check subscription
        if num_messages_for_client is not None:
            persist_help.check_subscription(port, client_id, subscription_topic, qos, 0)

    # Check stored message
    for i in range(num_base_msgs):
        msg_id = num_published_msgs - num_base_msgs + i
        payload = f"queued message {msg_id:3}"
        payload_b = payload.encode("UTF-8")
        mid = 10 + msg_id
        store_id = persist_help.check_base_msg(
            port,
            message_expiry,
            subscription_topic,
            payload_b,
            publisher_id,
            username,
            len(payload_b),
            mid,
            port,
            qos,
            retain=1 if i < retain_end else 0,
            idx=i,
        )
        # Check client msg
        for client_id, num_messages_for_client in client_msg_counts.items():
            if num_messages_for_client is None:
                continue
            client_msg_start = num_published_msgs - num_messages_for_client
            if msg_id < client_msg_start:
                continue
            cmsg_id = 1 + msg_id - client_msg_start
            subscriber_mid = cmsg_id
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
