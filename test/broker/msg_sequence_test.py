#!/usr/bin/env python3

# Test whether a valid CONNECT results in the correct CONNACK packet.

from mosq_test_helper import *
import importlib
from os import walk
import socket
import json
from collections import deque
import mosq_test
import mqtt_packets

send = 1
recv = 2
disconnected_check = 3
connected_check = 4
external_publish = 5
subscribe = 6
unsubscribe = 7


class SingleMsg(object):
    __slots__ = 'action', 'message', 'comment'
    def __init__(self, action, message, comment=''):
        self.action = action
        self.message = message
        self.comment = comment

class MsgSequence(object):
    __slots__ = 'name', 'msgs', 'msgs_all', 'expect_disconnect', 'port', 'protocol', 'proto_ver'

    def __init__(self, name, default_connect=True, port=1888, protocol='mqtt', proto_ver=4, expect_disconnect=True):
        self.name = name
        self.msgs_all = deque()
        self.expect_disconnect = expect_disconnect
        self.port = port
        self.protocol = protocol
        self.proto_ver = proto_ver
        if default_connect:
            self.add_default_connect(proto_ver=proto_ver)

    def add_default_connect(self, proto_ver):
        self.add_send(mqtt_packets.gen_connect(self.name, proto_ver=proto_ver))
        self.add_recv(mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver), "default connack")

    def add_send(self, message):
        self._add(send, message)

    def add_recv(self, message, comment):
        self._add(recv, message, comment)

    def add_external_publish(self, message, comment):
        self._add(external_publish, message, comment)

    def add_subscribe(self, message, comment):
        self._add(subscribe, message, comment)

    def add_unsubscribe(self, message, comment):
        self._add(unsubscribe, message, comment)

    def add_connected_check(self):
        self._add(connected_check, b"")

    def add_disconnected_check(self):
        self._add(disconnected_check, b"")

    def _add(self, action, message, comment=""):
        msg = SingleMsg(action, message, comment)
        self.msgs_all.append(msg)

    def _connected_check(self, sock):
        try:
            mosq_test.do_ping(sock)
        except (BrokenPipeError, mosq_test.TestError):
            raise ValueError("connection failed")

    def _send_message(self, sock, msg):
        sock.send(msg.message)

    def _publish_external_message(self, msg):
        sock = mosq_test.client_connect_only(hostname="localhost", port=self.port, timeout=2, protocol=self.protocol)
        sock.send(mqtt_packets.gen_connect("helper"))
        mosq_test.expect_packet(sock, "connack", mqtt_packets.gen_connack(rc=0))

        m = msg.message
        try:
            retain = m['retain']
        except KeyError:
            retain = False

        if m['qos'] == 0:
            sock.send(mqtt_packets.gen_publish(topic=m['topic'], qos=0, payload=m['payload'], retain=retain))
        elif m['qos'] == 1:
            sock.send(mqtt_packets.gen_publish(mid=1, qos=1, topic=m['topic'], payload=m['payload'], retain=retain))
            mosq_test.expect_packet(sock, "helper puback", mqtt_packets.gen_puback(mid=1))
        elif m['qos'] == 2:
            sock.send(mqtt_packets.gen_publish(mid=1, qos=2, topic=m['topic'], payload=m['payload'], retain=retain))
            mosq_test.expect_packet(sock, "helper pubrec", mqtt_packets.gen_pubrec(mid=1))
            sock.send(mqtt_packets.gen_pubrel(mid=1))
            mosq_test.expect_packet(sock, "helper pubcomp", mqtt_packets.gen_pubcomp(mid=1))
        sock.close()

    def _recv_message(self, sock, msg):
        data = sock.recv(len(msg.message))
        if data != msg.message:
            diff = list(data.hex())
            msghex = msg.message.hex()
            for i in range(len(diff)):
                if diff[i] == msghex[i]:
                    diff[i] = "."
            diff = "".join(diff)
            raise ValueError(f"Receive message {msg.comment}\nrec: {data.hex()}\nexp: {msghex}\ndiff:{diff}")

    def _subscribe(self, sock, msg):
        m = msg.message
        subscribe_packet = mqtt_packets.gen_subscribe(topic=m['topic'], qos=m['qos'], mid=1, proto_ver=self.proto_ver)
        suback_packet = mqtt_packets.gen_suback(qos=m['qos'], mid=1, proto_ver=self.proto_ver)
        mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

    def _unsubscribe(self, sock, msg):
        m = msg.message
        unsubscribe_packet = mqtt_packets.gen_unsubscribe(topic=m['topic'], mid=1, proto_ver=self.proto_ver)
        unsuback_packet = mqtt_packets.gen_unsuback(mid=1, proto_ver=self.proto_ver)
        mosq_test.do_send_receive(sock, unsubscribe_packet, unsuback_packet, "unsuback")

    def _disconnected_check(self, sock):
        try:
            data = sock.recv(1)
            if len(data) == 1 and self.expect_disconnect:
                raise ValueError("Still connected")
        except (ConnectionResetError, BlockingIOError):
            if self.expect_disconnect:
                pass
            else:
                raise

    def _process_message(self, sock, msg):
        if msg.action == send:
            self._send_message(sock, msg)
        elif msg.action == recv:
            self._recv_message(sock, msg)
        elif msg.action == external_publish:
            self._publish_external_message(msg)
        elif msg.action == disconnected_check:
            self._disconnected_check(sock)
        elif msg.action == connected_check:
            self._connected_check(sock)
        elif msg.action == subscribe:
            self._subscribe(sock, msg)
        elif msg.action == unsubscribe:
            self._unsubscribe(sock, msg)

    def process_next(self, sock):
        msg = self.msgs.popleft()
        self._process_message(sock, msg)

    def process_all(self, sock):
        self.msgs = self.msgs_all.copy()
        while len(self.msgs):
            self.process_next(sock)
        if self.expect_disconnect:
            self._disconnected_check(sock)
        else:
            self._connected_check(sock)


def parse_message(message):
    b = bytes()
    parts = message.split(" ")
    for i in range(0, len(parts)):
        if len(parts[i]) == 0:
            continue
        elif parts[i][0] in ['i']:
            # General 8-bit unsigned decimal
            b += int(parts[i][1:]).to_bytes(length=1, byteorder='big', signed=False)
        elif parts[i][0] in ['H', 'k', 'm', 's']:
            # General 16-bit unsigned decimal
            # Or 'k' keepalive specific
            # Or 'm' mid specific
            # Or 's' string specific
            b += int(parts[i][1:]).to_bytes(length=2, byteorder='big', signed=False)
        elif parts[i][0] == "L":
            # 32-bit unsigned decimal
            b += int(parts[i][1:]).to_bytes(length=4, byteorder='big', signed=False)
        elif parts[i][0] == "'":
            s = parts[i][1:]
            while s[-1] != "'" and i < len(parts)-1:
                i += 1
                s += " " + parts[i]
            if s[-1] != "'":
                raise ValueError(f"message {message} has incomplete string type")
            b += bytes(s[0:-1].encode('utf-8'))
        elif parts[i][0] in ['v', 'r']:
            # General variable length integer
            # Or 'r' remaining length
            v = int(parts[i][1:])

            # This allows non-compliant values >=2^28
            while True:
                byte = v % 128
                v = v // 128

                if v > 0:
                    byte = byte | 0x80
                b += byte.to_bytes(length=1, byteorder='big', signed=False)
                if v == 0:
                    break
        else:
            # hex
            try:
                b += bytes.fromhex(parts[i])
            except ValueError:
                raise ValueError(f"message {message} has invalid hex bytes")

    return b


def do_test(hostname, port, protocol):
    data_path=Path(__file__).resolve().parent/"data"
    rc = 0
    sequences = []
    for (_, _, filenames) in walk(data_path):
        sequences.extend(filenames)
        break

    total = 0
    succeeded = 0
    test = None
    failed_tests = []
    for seq in sorted(sequences):
        if seq[-5:] != ".json":
            continue

        with open(data_path/seq, "r") as f:
            test_file = json.load(f)

        for g in test_file:
            group_name = g["group"]
            try:
                disabled = g["disable"]
                if disabled:
                    continue
            except KeyError:
                pass
            try:
                g_proto_ver = g["ver"]
            except KeyError:
                g_proto_ver = 4
            try:
                g_connect = g["connect"]
            except KeyError:
                g_connect = True
            try:
                g_expect_disconnect = g["expect_disconnect"]
            except KeyError:
                g_expect_disconnect = True
            tests = g["tests"]

            for t in tests:
                tname = group_name + " " + t["name"]
                try:
                    proto_ver = t["ver"]
                except KeyError:
                    proto_ver = g_proto_ver
                try:
                    connect = t["connect"]
                except KeyError:
                    connect = g_connect
                try:
                    expect_disconnect = t["expect_disconnect"]
                except KeyError:
                    expect_disconnect = g_expect_disconnect

                this_test = MsgSequence(tname,
                        port=port,
                        protocol=protocol,
                        proto_ver=proto_ver,
                        expect_disconnect=expect_disconnect,
                        default_connect=connect)

                for m in t["msgs"]:
                    try:
                        c = m["comment"]
                    except KeyError:
                        c = ""
                    if m["type"] == "send":
                        this_test.add_send(parse_message(m["payload"]))
                    elif m["type"] == "recv":
                        this_test.add_recv(parse_message(m["payload"]), c)
                    elif m["type"] == "external_publish":
                        this_test.add_external_publish(m, c)
                    elif m["type"] == "subscribe":
                        this_test.add_subscribe(m, c)
                    elif m["type"] == "unsubscribe":
                        this_test.add_unsubscribe(m, c)

                total += 1
                try:
                    failed_tests.append(this_test)
                    sock = mosq_test.client_connect_only(hostname=hostname, port=port, timeout=2, protocol=protocol)
                    this_test.process_all(sock)
                    #print("\033[32m" + tname + "\033[0m")
                    succeeded += 1
                    sock.close()
                    failed_tests.pop()
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
                    exit()
                except mosq_test.TestError as e:
                    print("\033[31m" + tname + " failed: " + str(e) + "\033[0m")
                    rc = 1
                    sock.close()

    # Option to replay failed tests to make them easier to analyse.
    if False:
        for t in failed_tests:
            try:
                sock = mosq_test.client_connect_only(hostname=hostname, port=port, timeout=2, protocol=protocol)
                t.process_all(sock)
                length = len(data)
                print("\033[32m" + t.name + "\033[0m")
                sock.close()
            except ValueError as e:
                print("\033[31m" + t.name + " failed: " + str(e) + "\033[0m")
                rc = 1
                sock.close()
            except ConnectionResetError as e:
                print("\033[31m" + t.name + " failed: " + str(e) + "\033[0m")
                rc = 1
                sock.close()
            except socket.timeout as e:
                print("\033[31m" + t.name + " failed: " + str(e) + "\033[0m")
                rc = 1
                sock.close()
            except mosq_test.TestError as e:
                print("\033[31m" + t.name + " failed: " + str(e) + "\033[0m")
                rc = 1
                sock.close()

    print("%d tests total\n%d tests succeeded" % (total, succeeded))
    return rc


def write_config(filename, port, protocol):
    with open(filename, 'w') as f:
        f.write(f'listener {port}\n')
        f.write(f'protocol {protocol}\n')
        f.write("allow_anonymous true\n")
        f.write("log_type all\n")


def main(protocol):
    hostname = "localhost"
    port = mosq_test.get_port()
    conf_file = 'msg_sequence_test.conf'
    write_config(conf_file, port, protocol)
    broker = mosq_test.start_broker(filename=conf_file, port=port, use_conf=True, nolog=True)

    rc = 0
    try:
        rc = do_test(hostname=hostname, port=port, protocol=protocol)
    finally:
        mosq_test.terminate_broker(broker)
        os.remove(conf_file)
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1
        if broker.returncode != 0:
            rc = broker.returncode
            print(f"Broker exited with code {rc}. If there are no obvious errors this may be due to an ASAN build having leaks, which must be fixed.")
            print("The easiest way to reproduce this is to run the broker with `mosquitto -p 1888`, rerun the test, then quit the broker.")
        (stdo, stde) = broker.communicate()
    if rc:
        #print(stde.decode('utf-8'))
        exit(rc)

if __name__ == "__main__":
    #main(protocol="websockets")
    main(protocol="mqtt")
