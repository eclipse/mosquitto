#!/usr/bin/env python3

# Test whether a valid CONNECT results in the correct CONNACK packet.

from mosq_test_helper import *
import importlib
from os import walk
import socket
import json
from collections import deque
import mosq_test

send = 1
recv = 2
disconnected_check = 3
connected_check = 4
publish = 5


class SingleMsg(object):
    __slots__ = 'action', 'message', 'comment'
    def __init__(self, action, message, comment=''):
        self.action = action
        self.message = message
        self.comment = comment

class MsgSequence(object):
    __slots__ = 'name', 'msgs', 'expect_disconnect'

    def __init__(self, name, default_connect=True, proto_ver=4, expect_disconnect=True):
        self.name = name
        self.msgs = deque()
        self.expect_disconnect = expect_disconnect
        if default_connect:
            self.add_default_connect(proto_ver=proto_ver)

    def add_default_connect(self, proto_ver):
        self.add_send(mosq_test.gen_connect(self.name, proto_ver=proto_ver))
        self.add_recv(mosq_test.gen_connack(rc=0, proto_ver=proto_ver), "default connack")

    def add_send(self, message):
        self._add(send, message)

    def add_recv(self, message, comment):
        self._add(recv, message, comment)

    def add_publish(self, message, comment):
        self._add(publish, message, comment)

    def add_connected_check(self):
        self._add(connected_check, b"")

    def add_disconnected_check(self):
        self._add(disconnected_check, b"")

    def _add(self, action, message, comment=""):
        msg = SingleMsg(action, message, comment)
        self.msgs.append(msg)

    def _connected_check(self, sock):
        try:
            mosq_test.do_ping(sock)
        except mosq_test.TestError:
            raise ValueError("connection failed")

    def _send_message(self, sock, msg):
        sock.send(msg.message)

    def _publish_message(self, msg):
        sock = mosq_test.client_connect_only(hostname="localhost", port=1888, timeout=2)
        sock.send(mosq_test.gen_connect("helper"))
        mosq_test.expect_packet(sock, "connack", mosq_test.gen_connack(rc=0))

        m = msg.message
        if m['qos'] == 0:
            sock.send(mosq_test.gen_publish(topic=m['topic'], payload=m['payload']))
        elif m['qos'] == 1:
            sock.send(mosq_test.gen_publish(mid=1, qos=1, topic=m['topic'], payload=m['payload']))
            mosq_test.expect_packet(sock, "helper puback", mosq_test.gen_puback(mid=1))
        elif m['qos'] == 2:
            sock.send(mosq_test.gen_publish(mid=1, qos=2, topic=m['topic'], payload=m['payload']))
            mosq_test.expect_packet(sock, "helper pubrec", mosq_test.gen_pubrec(mid=1))
            sock.send(mosq_test.gen_pubrel(mid=1))
            mosq_test.expect_packet(sock, "helper pubcomp", mosq_test.gen_pubcomp(mid=1))
        sock.close()

    def _recv_message(self, sock, msg):
        data = sock.recv(len(msg.message))
        if data != msg.message:
            raise ValueError("Receive message %s | %s | %s" % (msg.comment, data, msg.message))


    def _disconnected_check(self, sock):
        try:
            data = sock.recv(1)
            if len(data) == 1 and self.expect_disconnect:
                raise ValueError("Still connected")
        except ConnectionResetError:
            if self.expect_disconnect:
                pass
            else:
                raise

    def _process_message(self, sock, msg):
        if msg.action == send:
            self._send_message(sock, msg)
        elif msg.action == recv:
            self._recv_message(sock, msg)
        elif msg.action == publish:
            self._publish_message(msg)
        elif msg.action == disconnected_check:
            self._disconnected_check(sock)
        elif msg.action == connected_check:
            self._connected_check(sock)

    def process_next(self, sock):
        msg = self.msgs.popleft()
        self._process_message(sock, msg)

    def process_all(self, sock):
        while len(self.msgs):
            self.process_next(sock)
        if self.expect_disconnect:
            self._disconnected_check(sock)
        else:
            self._connected_check(sock)


def do_test(hostname, port):
    rc = 0
    sequences = []
    for (_, _, filenames) in walk("data"):
        sequences.extend(filenames)
        break

    total = 0
    succeeded = 0
    test = None
    for seq in sorted(sequences):
        if seq[-5:] != ".json":
            continue

        with open("data/"+seq, "r") as f:
            test_file = json.load(f)

        for g in test_file:
            group_name = g["group"]
            try:
                disabled = g["disable"]
                if disabled:
                    continue
            except KeyError:
                pass
            tests = g["tests"]

            for t in tests:
                tname = group_name + " " + t["name"]
                try:
                    proto_ver = t["ver"]
                except KeyError:
                    proto_ver = 4
                try:
                    connect = t["connect"]
                except KeyError:
                    connect = True
                try:
                    expect_disconnect = t["expect_disconnect"]
                except KeyError:
                    expect_disconnect = True

                this_test = MsgSequence(tname,
                        proto_ver=proto_ver,
                        expect_disconnect=expect_disconnect,
                        default_connect=connect)

                for m in t["msgs"]:
                    try:
                        c = m["comment"]
                    except KeyError:
                        c = ""
                    if m["type"] == "send":
                        this_test.add_send(bytes.fromhex(m["payload"].replace(" ", "")))
                    elif m["type"] == "recv":
                        this_test.add_recv(bytes.fromhex(m["payload"].replace(" ", "")), c)
                    elif m["type"] == "publish":
                        this_test.add_publish(m, c)

                total += 1
                try:
                    sock = mosq_test.client_connect_only(hostname=hostname, port=port, timeout=2)
                    this_test.process_all(sock)
                    print("\033[32m" + tname + "\033[0m")
                    succeeded += 1
                    sock.close()
                except ValueError as e:
                    print("\033[31m" + tname + " failed: " + str(e) + "\033[0m")
                    rc = 1
                    sock.close()
                except ConnectionResetError as e:
                    print("\033[31m" + tname + " failed: " + str(e) + "\033[0m")
                    rc = 1
                    sock.close()
                except socket.timeout as e:
                    print("\033[31m" + tname + " failed: " + str(e) + "\033[0m")
                    rc = 1
                    sock.close()
                except mosq_test.TestError as e:
                    print("\033[31m" + tname + " failed: " + str(e) + "\033[0m")
                    rc = 1
                    sock.close()

    print("%d tests total\n%d tests succeeded" % (total, succeeded))
    return rc

hostname = "localhost"
port = mosq_test.get_port()
broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port, nolog=True)

rc = 0
try:
    rc = do_test(hostname=hostname, port=port)
finally:
    broker.terminate()
    if mosq_test.wait_for_subprocess(broker):
        print("broker not terminated")
        if rc == 0: rc=1
    (stdo, stde) = broker.communicate()
if rc:
    #print(stde.decode('utf-8'))
    exit(rc)
