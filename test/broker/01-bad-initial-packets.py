#!/usr/bin/env python3

# Test whether non-CONNECT packets as an initial packet can cause excess memory use

from mosq_test_helper import *

from broker_config import BrokerConfig, ListenerConfig
from mosquitto_broker import MosquittoBroker
try:
    import psutil
except ModuleNotFoundError:
    print("WARNING: Test not running due to missing psutil module")
    exit(77)


def do_send(port, socks, payload):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.append(sock)
    sock.connect(("127.0.0.1", port))
    try:
        sock.send(payload)
    except (ConnectionResetError, BrokenPipeError):
        pass


def do_test():
    port = mosq_test.get_port()
    broker_config = BrokerConfig(
        listeners = [ ListenerConfig(port=port) ],
        allow_anonymous=True,
        sys_interval=1,
    )
    broker = MosquittoBroker(config=broker_config)
    # Get the base memory useage before any connection attempt has happen
    with broker:
        base_mem = psutil.Process(broker.process.pid).memory_info().vms
        socks = []

        do_send(port, socks, b"\x20\x80\x80\x80t" + b"\01"*100000000) # CONNACK
        do_send(port, socks, b"\x30\x80\x80\x80t" + b"\01"*100000000) # PUBLISH
        do_send(port, socks, b"\x40\x80\x80\x80t" + b"\01"*100000000) # PUBACK
        do_send(port, socks, b"\x50\x80\x80\x80t" + b"\01"*100000000) # PUBREC
        do_send(port, socks, b"\x60\x80\x80\x80t" + b"\01"*100000000) # PUBREL
        do_send(port, socks, b"\x70\x80\x80\x80t" + b"\01"*100000000) # PUBCOMP
        do_send(port, socks, b"\x80\x80\x80\x80t" + b"\01"*100000000) # SUBSCRIBE
        do_send(port, socks, b"\x90\x80\x80\x80t" + b"\01"*100000000) # SUBACK
        do_send(port, socks, b"\xA0\x80\x80\x80t" + b"\01"*100000000) # UNSUBSCRIBE
        do_send(port, socks, b"\xB0\x80\x80\x80t" + b"\01"*100000000) # UNSUBACK
        do_send(port, socks, b"\xC0\x80\x80\x80t" + b"\01"*100000000) # PINGREQ
        do_send(port, socks, b"\xD0\x80\x80\x80t" + b"\01"*100000000) # PINGRESP
        do_send(port, socks, b"\xE0\x80\x80\x80t" + b"\01"*100000000) # DISCONNECT
        do_send(port, socks, b"\xF0\x80\x80\x80t" + b"\01"*100000000) # AUTH

        mem = psutil.Process(broker.process.pid).memory_info().vms - base_mem

        for s in socks:
            s.close()

        limit = 20000000
        if mem > limit:
            raise mosq_test.TestError(f"Process memory {mem} greater than limit of {limit}")


do_test()
