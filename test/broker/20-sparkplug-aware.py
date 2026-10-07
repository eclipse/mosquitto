#!/usr/bin/env python3

from mosq_test_helper import *

from broker_config import BrokerConfig, PluginConfig
from mosquitto_broker import MosquittoBroker
import uuid

mosq_test.require_features(["WITH_PLUGINS", "WITH_PLUGIN_SPARKPLUG_AWARE"])

namespace = "spBv1.0"
client_id = "test-client"
username = None
password = None


def proc(port, proto_ver):
    group_id = str(uuid.uuid4())
    edge_node_id = str(uuid.uuid4())
    device_id = str(uuid.uuid4())

    # ======================================================================
    # Connect a client to monitor the spBv1.0/<group_id>/NDEATH/# and
    # $sparkplug/certificates/spBv1.0/<group_id>/# topics
    # ======================================================================

    topic = f"$sparkplug/certificates/{namespace}/{group_id}/#"
    qos = 1
    monitor = mosq_test.sub_helper(port, topic, qos=qos, proto_ver=proto_ver)

    topic = f"{namespace}/{group_id}/NDEATH/#"
    qos = 1
    subscribe_packet = mqtt_packets.gen_subscribe(topic=topic, mid=1, qos=qos, proto_ver=proto_ver)
    suback_packet = mqtt_packets.gen_suback(mid=1, qos=qos, proto_ver=proto_ver)
    mosq_test.do_send_receive(monitor, subscribe_packet, suback_packet)

    # ======================================================================
    # Connect a test client that will act as a sparkplug device
    # ======================================================================

    # • [tck-id-message-flow-edge-node-birth-publish-will-message-topic]
    #   The Edge Node’s MQTT Will Message’s topic MUST be of the form
    #   spBv1.0/group_id/NDEATH/edge_node_id where group_id is the Sparkplug
    #   Group ID and the edge_node_id is the Sparkplug Edge Node ID for this
    #   Edge Node
    NDEATH_topic = f"{namespace}/{group_id}/NDEATH/{edge_node_id}"

    # • [tck-id-message-flow-edge-node-birth-publish-will-message-payload]
    #   The Edge Node’s MQTT Will Message’s payload MUST be a Sparkplug Google
    #   Protobuf encoded payload.
    # • [tck-id-message-flow-edge-node-birth-publish-will-message-payload-bdSeq]
    #   The Edge Node’s MQTT Will Message’s payload MUST include a metric with
    #   the name of bdSeq, the datatype of INT64, and the value MUST be
    #   incremented by one from the value in the previous MQTT CONNECT packet
    #   unless the value would be greater than 255. If in the previous NBIRTH a
    #   value of 255 was sent, the next MQTT Connect packet Will Message
    #   payload bdSeq number value MUST have a value of 0.
    NDEATH_payload = ""

    # • [tck-id-message-flow-edge-node-birth-publish-will-message-qos]
    #   The Edge Node’s MQTT Will Message’s MQTT QoS MUST be 1.
    NDEATH_qos = 1

    # • [tck-id-message-flow-edge-node-birth-publish-will-message-will-retained]
    #   The Edge Node’s MQTT Will Message’s retained flag MUST be set to false.
    NDEATH_retain = False

    # • [tck-id-principles-persistence-clean-session-311]
    #   If the MQTT client is using MQTT v3.1.1, the Edge Node’s MQTT CONNECT
    #   packet MUST set the Clean Session flag to true.
    # • [tck-id-principles-persistence-clean-session-50]
    #   If the MQTT client is using MQTT v5.0, the Edge Node’s MQTT CONNECT
    #   packet MUST set the Clean Start flag to true and the Session Expiry
    #   Interval to 0.
    clean_session = True
    session_expiry_interval = 0

    # • [tck-id-message-flow-edge-node-birth-publish-connect]
    #   Any Edge Node in the MQTT infrastructure MUST establish an MQTT Session
    #   prior to publishing NBIRTH and DBIRTH messages.
    # • [tck-id-message-flow-edge-node-birth-publish-will-message]
    #   When a Sparkplug Edge Node sends its MQTT CONNECT packet, it MUST
    #   include a Will Message.
    connect_packet = mqtt_packets.gen_connect(client_id, clean_session=clean_session, username=username, password=password,
                                           will_topic=NDEATH_topic, will_qos=NDEATH_qos, will_retain=NDEATH_retain,
                                           will_payload=NDEATH_payload, proto_ver=proto_ver, session_expiry=session_expiry_interval)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)
    test_client = mosq_test.do_client_connect(connect_packet, connack_packet, port=port, connack_error=f"client connack")

    # • [tck-id-message-flow-edge-node-ncmd-subscribe]
    #   The MQTT client associated with the Edge Node MUST subscribe to a topic
    #   of the form spBv1.0/group_id/NCMD/edge_node_id where group_id is the
    #   Sparkplug Group ID and the edge_node_id is the Sparkplug Edge Node ID
    #   for this Edge Node. It MUST subscribe on this topic with a QoS of 1.
    NCMD_topic = f"{namespace}/{group_id}/NCMD/{edge_node_id}"
    qos = 1

    subscribe_packet = mqtt_packets.gen_subscribe(topic=NCMD_topic, mid=1, qos=qos, proto_ver=proto_ver)
    suback_packet = mqtt_packets.gen_suback(mid=1, qos=qos, proto_ver=proto_ver)
    mosq_test.do_send_receive(test_client, subscribe_packet, suback_packet)

    # ======================================================================
    # Test client publishes its NBIRTH certificate
    # ======================================================================

    # • [tck-id-message-flow-edge-node-birth-publish-nbirth-topic]
    #   The Edge Node’s NBIRTH MQTT topic MUST be of the form
    #   spBv1.0/group_id/NBIRTH/edge_node_id where group_id is the Sparkplug
    #   Group ID and the edge_node_id is the Sparkplug Edge Node ID for this
    #   Edge Node
    NBIRTH_topic = f"{namespace}/{group_id}/NBIRTH/{edge_node_id}"

    # • [tck-id-message-flow-edge-node-birth-publish-nbirth-payload]
    #   The Edge Node’s NBIRTH payload MUST be a Sparkplug Google Protobuf
    #   encoded payload.
    # • [tck-id-message-flow-edge-node-birth-publish-nbirth-payload-bdSeq]
    #   The Edge Node’s NBIRTH payload MUST include a metric with the name of
    #   bdSeq the datatype of INT64 and the value MUST be the same as the
    #   previous MQTT CONNECT packet.
    # • [tck-id-message-flow-edge-node-birth-publish-nbirth-payload-seq]
    #   The Edge Node’s NBIRTH payload MUST include a seq number that is
    #   between 0 and 255 (inclusive).
    #   ◦ This will become the starting sequence number which all following
    #     messages will include a sequence number that is one more than the
    #     previous up to 255 where it wraps back to zero.
    # • [tck-id-principles-birth-certificates-order]
    #   Birth Certificates MUST be the first MQTT messages published by any
    #   Edge Node or any Host Application.
    NBIRTH_payload = "FIXME"

    # • [tck-id-message-flow-edge-node-birth-publish-nbirth-qos]
    #   The Edge Node’s NBIRTH MQTT QoS MUST be 0.
    NBIRTH_qos = 0

    # • [tck-id-message-flow-edge-node-birth-publish-nbirth-retained]
    #   The Edge Node’s NBIRTH retained flag MUST be set to false.
    NBIRTH_retain = False

    publish_packet = mqtt_packets.gen_publish(topic=NBIRTH_topic, qos=NBIRTH_qos, payload=NBIRTH_payload, retain=NBIRTH_retain, proto_ver=proto_ver)
    test_client.send(publish_packet)

    # **********************************************************************
    # Monitor client should receive the NBIRTH certificate republished by the
    # broker
    # **********************************************************************

    NBIRTH_topic_aware = f"$sparkplug/certificates/{namespace}/{group_id}/NBIRTH/{edge_node_id}"
    publish_packet = mqtt_packets.gen_publish(NBIRTH_topic_aware, mid=1, qos=0, proto_ver=proto_ver, payload=NBIRTH_payload)
    mosq_test.expect_packet(monitor, "error1", publish_packet)

    # ======================================================================
    # Test client publishes its DBIRTH certificate
    # ======================================================================

    # • [tck-id-message-flow-device-birth-publish-dbirth-match-edge-node-topic]
    #   The Device’s DBIRTH MQTT topic group_id and edge_node_id MUST match the
    #   group_id and edge_node_id that were sent in the prior NBIRTH message
    #   for the Edge Node this Device is associated with.
    # • [tck-id-message-flow-device-birth-publish-dbirth-topic]
    #   The Device’s DBIRTH MQTT topic MUST be of the form
    #   spBv1.0/group_id/DBIRTH/edge_node_id/device_id where group_id is the
    #   Sparkplug Group ID the edge_node_id is the Sparkplug Edge Node ID and
    #   the device_id is the Sparkplug Device ID for this Device.
    DBIRTH_topic = f"{namespace}/{group_id}/DBIRTH/{edge_node_id}/{device_id}"

    # • [tck-id-message-flow-device-birth-publish-dbirth-payload]
    #   The Device’s DBIRTH payload MUST be a Sparkplug Google Protobuf encoded
    #   payload.
    # • [tck-id-message-flow-device-birth-publish-dbirth-payload-seq]
    #   The Device’s DBIRTH payload MUST include a seq number that is between 0
    #   and 255 (inclusive) and be one more than was included in the prior
    #   Sparkplug message sent from the Edge Node associated with this Device.
    DBIRTH_payload = "FIXME"

    # • [tck-id-message-flow-device-birth-publish-dbirth-qos]
    #   The Device’s DBIRTH MQTT QoS MUST be 0.
    DBIRTH_qos = 0

    # • [tck-id-message-flow-device-birth-publish-dbirth-retained]
    #   The Device’s DBIRTH retained flag MUST be set to false.
    DBIRTH_retain = False

    # • [tck-id-message-flow-device-birth-publish-nbirth-wait]
    #   The NBIRTH message MUST have been sent within the current MQTT session
    #   prior to a DBIRTH being published.
    publish_packet = mqtt_packets.gen_publish(topic=DBIRTH_topic, qos=DBIRTH_qos, payload=DBIRTH_payload, retain=DBIRTH_retain, proto_ver=proto_ver)
    test_client.send(publish_packet)

    # **********************************************************************
    # Monitor client should receive the DBIRTH certificate republished by the
    # broker
    # **********************************************************************

    DBIRTH_topic_aware = f"$sparkplug/certificates/{namespace}/{group_id}/DBIRTH/{edge_node_id}/{device_id}"
    publish_packet = mqtt_packets.gen_publish(DBIRTH_topic_aware, mid=1, qos=0, proto_ver=proto_ver, payload=DBIRTH_payload)
    mosq_test.expect_packet(monitor, "error0", publish_packet)

    # ======================================================================
    # The test client disconnects "unintentionally"
    # ======================================================================

    # • [tck-id-operational-behavior-edge-node-intentional-disconnect-ndeath]
    #   When an Edge Node disconnects intentionally, it MUST publish an NDEATH
    #   before terminating the connection.
    # • [tck-id-operational-behavior-edge-node-intentional-disconnect-packet]
    #   Immediately the NDEATH publish, a DISCONNECT packet MAY be sent to the
    #   MQTT Server.

    test_client.close()

    # **********************************************************************
    # Monitor client should receive the NDEATH certificate
    # **********************************************************************

    publish_packet = mqtt_packets.gen_publish(NDEATH_topic, mid=1, qos=NDEATH_qos, proto_ver=proto_ver, payload=NDEATH_payload)
    mosq_test.expect_packet(monitor, "error 2", publish_packet)

    # **********************************************************************
    # Clear the republished certificates ready for the next test
    # **********************************************************************
    publish_packet = mqtt_packets.gen_publish(NBIRTH_topic_aware, qos=0, proto_ver=proto_ver, payload=None, retain=True)
    monitor.send(publish_packet)
    publish_packet = mqtt_packets.gen_publish(DBIRTH_topic_aware, qos=0, proto_ver=proto_ver, payload=None, retain=True)
    monitor.send(publish_packet)
    monitor.close()


def do_tests():
    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        plugins=[PluginConfig(mosq_paths.plugin_sparkplug_aware)],
        allow_anonymous=True,
    )
    broker = MosquittoBroker(port=port, config=broker_config)
    with broker:
        proc(port, 4)
        proc(port, 5)

if __name__ == '__main__':
    do_tests()
