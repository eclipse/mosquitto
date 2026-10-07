#!/usr/bin/env python3

# Test whether a client subscribed to a topic receives its own message sent to that topic.

from mosq_test_helper import *

from broker_config import BrokerConfig
from mosquitto_broker import MosquittoBroker

mosq_test.require_features(["WITH_PERSISTENCE"])

def do_test():
    connect_packet = mqtt_packets.gen_connect("persistent-test", clean_session=True)
    connack_packet = mqtt_packets.gen_connack(rc=0)

    publish_packet = mqtt_packets.gen_publish("subpub/qos1", qos=1, mid=1, payload="message", retain=True)
    puback_packet = mqtt_packets.gen_puback(1)

    port = mosq_test.get_port()
    dbfile = f"mosquitto-{port}.db"

    if os.path.exists(dbfile):
        os.unlink(dbfile)

    broker_config = BrokerConfig(
        persistence=True,
        persistence_file=dbfile,
        autosave_interval=1,
        autosave_on_changes=True,
    )
    broker = MosquittoBroker(port=port, config=broker_config)
    broker.add_extra_file(dbfile)
    with broker:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        mosq_test.do_send_receive(sock, publish_packet, puback_packet, "puback")
        sock.close()

        time.sleep(0.5)
        if not os.path.exists(dbfile):
            raise RuntimeError(f"{dbfile} not created")

do_test()
