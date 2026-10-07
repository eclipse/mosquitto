#!/usr/bin/env python3

# Connect a client, add a subscription, disconnect, send a message with a
# different client, restore, reconnect, check it is received.

from mosq_test_helper import *
from persist_module_helper import *
from typing import Optional

import mqtt5_rc
import mqtt5_props

persist_help = persist_module()

port, _ = mosq_test.get_port(2)

proto_ver = 5
qos = 1
topic = "test-will-msg"
username = "test-will-msg"

subscriber_id = "test-will-subscriber"
publisher_id = "test-will-publisher"

will_properties = mqtt5_props.gen_properties(
    [
        {"identifier": mqtt5_props.PAYLOAD_FORMAT_INDICATOR, "value": 1},
        {"identifier": mqtt5_props.CONTENT_TYPE, "value": "text"},
        {
            "identifier": mqtt5_props.USER_PROPERTY,
            "name": "test-user-property",
            "value": "nothing important",
        },
    ]
)

will_properties_in_db = (
    "["
    '{"identifier":"payload-format-indicator","value":1}'
    + ',{"identifier":"content-type","value":"text"}'
    + ',{"identifier":"user-property","name":"test-user-property","value":"nothing important"}'
    + "]"
)

send_will_disconnect_rc = mqtt5_rc.DISCONNECT_WITH_WILL_MSG
normal_disconnect_rc = mqtt5_rc.NORMAL_DISCONNECTION


def do_test(
    session_expiry: int,
    will_qos: int,
    will_retain: bool,
    will_delay: int = 0,
    disconnect_rc: Optional[int] = None,
):
    mid = 1

    print(
        f" {'persistent' if session_expiry > 0 else 'non persistent'} client"
        f" with will qos = {will_qos}"
        f", will_retain = {will_retain}"
        f" and will delay = {will_delay}"
        + (f" and disconnect rc = {disconnect_rc}" if disconnect_rc is not None else "")
    )

    def check_will_received(do_subscribe: bool, expect_will_publish=bool):
        nonlocal mid
        # Reconnect client, it should have a session
        subscriber_sock = connect_client(
            port,
            subscriber_id,
            username,
            proto_ver,
            session_expiry=60,
            session_present=True,
            subscribe_topic=topic if do_subscribe else None,
        )
        if expect_will_publish:
            will_publish = mqtt_packets.gen_publish(
                topic,
                will_qos,
                will_payload,
                will_retain and do_subscribe,
                mid=mid,
                proto_ver=proto_ver,
                properties=will_properties,
            )
            if will_qos > 0:
                pub_ack = mqtt_packets.gen_puback(mid=1, proto_ver=proto_ver)
                mosq_test.do_receive_send(subscriber_sock, will_publish, pub_ack)
            else:
                mosq_test.expect_packet(subscriber_sock, "will message", will_publish)
            mid += 1
        # Always send a ping. Either to make sure a potential puback is processed by the server
        # or to make sure the server has not send an unexpected publish
        mosq_test.do_ping(subscriber_sock)
        subscriber_sock.close()

    expect_will_received = will_qos > 0

    conf_file = os.path.basename(__file__).replace(".py", f"_{port}.conf")
    persist_help.write_config(
        conf_file,
        port,
        additional_config_entries={"plugin_opt_flush_period": 0, "log_type": "all"},
    )
    persist_help.init(port)

    rc = 1

    will_payload = b"My simple will message"
    if will_delay:
        will_delay_property = mqtt5_props.gen_uint32_prop(
            mqtt5_props.WILL_DELAY_INTERVAL, will_delay
        )
    else:
        will_delay_property = b""
    will_delayed = will_delay > 0 and session_expiry > 0

    broker = mosq_test.start_broker(filename=conf_file, use_conf=True, port=port)
    stde = None
    stde2 = None
    try:
        subscriber_sock = connect_client(
            port,
            subscriber_id,
            username,
            proto_ver,
            session_expiry=60,
            subscribe_topic=topic,
        )  # .close()

        publisher_sock = connect_client(
            port,
            publisher_id,
            username,
            proto_ver,
            session_expiry=session_expiry,
            will_topic=topic,
            will_qos=will_qos,
            will_retain=will_retain,
            will_payload=will_payload,
            will_properties=will_properties + will_delay_property,
        )
        if disconnect_rc:
            if disconnect_rc == mqtt5_rc.SESSION_TAKEN_OVER:
                publisher_sock = connect_client(
                    port,
                    publisher_id,
                    username,
                    proto_ver,
                    session_expiry=session_expiry,
                    session_present=session_expiry > 0,
                )
                # Do a ping to make sure the new connection is functional
                mosq_test.do_ping(publisher_sock)
            else:
                mosq_test.do_send(
                    publisher_sock,
                    mqtt_packets.gen_disconnect(
                        reason_code=disconnect_rc, proto_ver=proto_ver
                    ),
                )
            will_sent = disconnect_rc != normal_disconnect_rc and not will_delayed
        else:
            will_sent = False

        # Do check whilst broker is still running, the retry on check_*() will
        # ensure that the changes are committed to disk before the broker is killed
        if will_sent and will_qos > 0:
            num_client_msgs = 1
        else:
            num_client_msgs = 0
        num_retain = 1 if will_retain > 0 and will_sent else 0
        num_base_msgs = max(num_client_msgs, num_retain)
        num_wills = 0 if will_sent else 1
        persist_help.check_counts(
            port,
            clients=1 if session_expiry == 0 else 2,
            base_msgs=num_base_msgs,
            client_msgs_out=num_client_msgs,
            retain_msgs=num_retain,
            subscriptions=1,
            wills=0 if will_sent else 1,
        )
        if not will_sent:
            persist_help.check_will(
                port,
                publisher_id,
                will_payload,
                topic,
                will_qos,
                will_retain,
                properties=will_properties_in_db,
            )

        # Kill the broker
        broker.kill()
        stde = mosq_test.broker_log(broker)
        broker = None

        # Restart broker
        broker = mosq_test.start_broker(filename=conf_file, use_conf=True, port=port)

        check_will_received(
            do_subscribe=False, expect_will_publish=will_qos > 0 and not will_delayed
        )
        check_will_received(
            do_subscribe=True, expect_will_publish=will_retain and not will_delayed
        )

        (broker_terminate_rc, stde2) = mosq_test.terminate_broker(broker)
        broker = None

        rc = broker_terminate_rc
    finally:
        if broker is not None:
            mosq_test.terminate_broker(broker)
            if mosq_test.wait_for_subprocess(broker):
                if rc == 0:
                    rc = 1
            stde3 = mosq_test.broker_log(broker)
            if not stde:
                stde = stde3
            else:
                stde2 = stde3
        os.remove(conf_file)
        rc += persist_help.cleanup(port)

        if rc:
            if stde:
                print(stde)
            if stde2:
                print("Broker after restart")
                print(stde2)
        # assert rc == 0, f"rc: {rc}"
