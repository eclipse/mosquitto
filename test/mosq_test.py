import errno
import os
import socket
import subprocess
import struct
import sys
import time

import mqtt5_props

import __main__

import atexit
vg_index = 1
vg_logfiles = []


class TestError(Exception):
    def __init__(self, message="Mismatched packets"):
        self.message = message

def start_broker(filename, cmd=None, port=0, use_conf=False, expect_fail=False):
    global vg_index
    global vg_logfiles

    delay = 0.1

    if use_conf == True:
        cmd = ['../../src/mosquitto', '-v', '-c', filename.replace('.py', '.conf')]

        if port == 0:
            port = 1888
    else:
        if cmd is None and port != 0:
            cmd = ['../../src/mosquitto', '-v', '-p', str(port)]
        elif cmd is None and port == 0:
            port = 1888
            cmd = ['../../src/mosquitto', '-v', '-c', filename.replace('.py', '.conf')]
        elif cmd is not None and port == 0:
            port = 1888

    if os.environ.get('MOSQ_USE_VALGRIND') is not None:
        logfile = filename+'.'+str(vg_index)+'.vglog'
        cmd = ['valgrind', '-q', '--trace-children=yes', '--leak-check=full', '--show-leak-kinds=all', '--log-file='+logfile] + cmd
        vg_logfiles.append(logfile)
        vg_index += 1
        delay = 1

    #print(port)
    #print(cmd)
    broker = subprocess.Popen(cmd, stderr=subprocess.PIPE)
    for i in range(0, 20):
        time.sleep(delay)
        c = None
        try:
            c = socket.create_connection(("localhost", port))
        except socket.error as err:
            if err.errno != errno.ECONNREFUSED:
                raise

        if c is not None:
            c.close()
            time.sleep(delay)
            return broker

    if expect_fail == False:
        outs, errs = broker.communicate(timeout=1)
        print("FAIL: unable to start broker: %s" % errs)
        raise IOError
    else:
        return None

def start_client(filename, cmd, env, port=1888):
    if cmd is None:
        raise ValueError
    if os.environ.get('MOSQ_USE_VALGRIND') is not None:
        cmd = ['valgrind', '-q', '--log-file='+filename+'.vglog'] + cmd

    cmd = cmd + [str(port)]
    return subprocess.Popen(cmd, env=env)


def expect_packet(sock, name, expected):
    if len(expected) > 0:
        rlen = len(expected)
    else:
        rlen = 1

    packet_recvd = sock.recv(rlen)
    if packet_matches(name, packet_recvd, expected):
        return True
    else:
        raise TestError


def packet_matches(name, recvd, expected):
    if recvd != expected:
        print("FAIL: Received incorrect "+name+".")
        try:
            print("Received: "+to_string(recvd))
        except struct.error:
            print("Received (not decoded, len=%d): %s" % (len(recvd), recvd))
        try:
            print("Expected: "+to_string(expected))
        except struct.error:
            print("Expected (not decoded, len=%d): %s" % (len(expected), expected))

        return False
    else:
        return True


def receive_unordered(sock, recv1_packet, recv2_packet, error_string):
    expected1 = recv1_packet + recv2_packet
    expected2 = recv2_packet + recv1_packet
    recvd = b''
    while len(recvd) < len(expected1):
        r = sock.recv(1)
        if len(r) == 0:
            raise ValueError(error_string)
        recvd += r

    if recvd == expected1 or recvd == expected2:
        return
    else:
        packet_matches(error_string, recvd, expected2)
        raise ValueError(error_string)


def do_send_receive(sock, send_packet, receive_packet, error_string="send receive error"):
    size = len(send_packet)
    total_sent = 0
    while total_sent < size:
        sent = sock.send(send_packet[total_sent:])
        if sent == 0:
            raise RuntimeError("socket connection broken")
        total_sent += sent

    if expect_packet(sock, error_string, receive_packet):
        return sock
    else:
        sock.close()
        raise ValueError


# Useful for mocking a client receiving (with ack) a qos1 publish
def do_receive_send(sock, receive_packet, send_packet, error_string="receive send error"):
    if expect_packet(sock, error_string, receive_packet):
        size = len(send_packet)
        total_sent = 0
        while total_sent < size:
            sent = sock.send(send_packet[total_sent:])
            if sent == 0:
                raise RuntimeError("socket connection broken")
            total_sent += sent
        return sock
    else:
        sock.close()
        raise ValueError


def do_client_connect(connect_packet, connack_packet, hostname="localhost", port=1888, timeout=10, connack_error="connack"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((hostname, port))

    return do_send_receive(sock, connect_packet, connack_packet, connack_error)


def remaining_length(packet):
    l = min(5, len(packet))
    all_bytes = struct.unpack("!"+"B"*l, packet[:l])
    mult = 1
    rl = 0
    for i in range(1,l-1):
        byte = all_bytes[i]

        rl += (byte & 127) * mult
        mult *= 128
        if byte & 128 == 0:
            packet = packet[i+1:]
            break

    return (packet, rl)


def to_hex_string(packet):
    if len(packet) == 0:
        return ""

    s = ""
    while len(packet) > 0:
        packet0 = struct.unpack("!B", packet[0])
        s = s+hex(packet0[0]) + " "
        packet = packet[1:]

    return s


def to_string(packet):
    if len(packet) == 0:
        return ""

    packet0 = struct.unpack("!B%ds" % (len(packet)-1), bytes(packet))
    packet0 = packet0[0]
    cmd = packet0 & 0xF0
    if cmd == 0x00:
        # Reserved
        return "0x00"
    elif cmd == 0x10:
        # CONNECT
        (packet, rl) = remaining_length(packet)
        pack_format = "!H" + str(len(packet)-2) + 's'
        (slen, packet) = struct.unpack(pack_format, packet)
        pack_format = "!" + str(slen)+'sBBH' + str(len(packet)-slen-4) + 's'
        (protocol, proto_ver, flags, keepalive, packet) = struct.unpack(pack_format, packet)
        s = "CONNECT, proto="+str(protocol)+str(proto_ver)+", keepalive="+str(keepalive)
        if flags&2:
            s = s+", clean-session"
        else:
            s = s+", durable"

        pack_format = "!H" + str(len(packet)-2) + 's'
        (slen, packet) = struct.unpack(pack_format, packet)
        pack_format = "!" + str(slen)+'s' + str(len(packet)-slen) + 's'
        (client_id, packet) = struct.unpack(pack_format, packet)
        s = s+", id="+str(client_id)

        if flags&4:
            pack_format = "!H" + str(len(packet)-2) + 's'
            (slen, packet) = struct.unpack(pack_format, packet)
            pack_format = "!" + str(slen)+'s' + str(len(packet)-slen) + 's'
            (will_topic, packet) = struct.unpack(pack_format, packet)
            s = s+", will-topic="+str(will_topic)

            pack_format = "!H" + str(len(packet)-2) + 's'
            (slen, packet) = struct.unpack(pack_format, packet)
            pack_format = "!" + str(slen)+'s' + str(len(packet)-slen) + 's'
            (will_message, packet) = struct.unpack(pack_format, packet)
            s = s+", will-message="+will_message

            s = s+", will-qos="+str((flags&24)>>3)
            s = s+", will-retain="+str((flags&32)>>5)

        if flags&128:
            pack_format = "!H" + str(len(packet)-2) + 's'
            (slen, packet) = struct.unpack(pack_format, packet)
            pack_format = "!" + str(slen)+'s' + str(len(packet)-slen) + 's'
            (username, packet) = struct.unpack(pack_format, packet)
            s = s+", username="+str(username)

        if flags&64:
            pack_format = "!H" + str(len(packet)-2) + 's'
            (slen, packet) = struct.unpack(pack_format, packet)
            pack_format = "!" + str(slen)+'s' + str(len(packet)-slen) + 's'
            (password, packet) = struct.unpack(pack_format, packet)
            s = s+", password="+str(password)

        if flags&1:
            s = s+", reserved=1"

        return s
    elif cmd == 0x20:
        # CONNACK
        (cmd, rl, resv, rc) = struct.unpack('!BBBB', packet)
        return "CONNACK, rl="+str(rl)+", res="+str(resv)+", rc="+str(rc)
    elif cmd == 0x30:
        # PUBLISH
        dup = (packet0 & 0x08)>>3
        qos = (packet0 & 0x06)>>1
        retain = (packet0 & 0x01)
        (packet, rl) = remaining_length(packet)
        pack_format = "!H" + str(len(packet)-2) + 's'
        (tlen, packet) = struct.unpack(pack_format, packet)
        pack_format = "!" + str(tlen)+'s' + str(len(packet)-tlen) + 's'
        (topic, packet) = struct.unpack(pack_format, packet)
        s = "PUBLISH, rl="+str(rl)+", topic="+str(topic)+", qos="+str(qos)+", retain="+str(retain)+", dup="+str(dup)
        if qos > 0:
            pack_format = "!H" + str(len(packet)-2) + 's'
            (mid, packet) = struct.unpack(pack_format, packet)
            s = s + ", mid="+str(mid)

        s = s + ", payload="+str(packet)
        return s
    elif cmd == 0x40:
        # PUBACK
        (cmd, rl, mid) = struct.unpack('!BBH', packet)
        return "PUBACK, rl="+str(rl)+", mid="+str(mid)
    elif cmd == 0x50:
        # PUBREC
        (cmd, rl, mid) = struct.unpack('!BBH', packet)
        return "PUBREC, rl="+str(rl)+", mid="+str(mid)
    elif cmd == 0x60:
        # PUBREL
        dup = (packet0 & 0x08)>>3
        (cmd, rl, mid) = struct.unpack('!BBH', packet)
        return "PUBREL, rl="+str(rl)+", mid="+str(mid)+", dup="+str(dup)
    elif cmd == 0x70:
        # PUBCOMP
        (cmd, rl, mid) = struct.unpack('!BBH', packet)
        return "PUBCOMP, rl="+str(rl)+", mid="+str(mid)
    elif cmd == 0x80:
        # SUBSCRIBE
        (packet, rl) = remaining_length(packet)
        pack_format = "!H" + str(len(packet)-2) + 's'
        (mid, packet) = struct.unpack(pack_format, packet)
        s = "SUBSCRIBE, rl="+str(rl)+", mid="+str(mid)
        topic_index = 0
        while len(packet) > 0:
            pack_format = "!H" + str(len(packet)-2) + 's'
            (tlen, packet) = struct.unpack(pack_format, packet)
            pack_format = "!" + str(tlen)+'sB' + str(len(packet)-tlen-1) + 's'
            (topic, qos, packet) = struct.unpack(pack_format, packet)
            s = s + ", topic"+str(topic_index)+"="+str(topic)+","+str(qos)
        return s
    elif cmd == 0x90:
        # SUBACK
        (packet, rl) = remaining_length(packet)
        pack_format = "!H" + str(len(packet)-2) + 's'
        (mid, packet) = struct.unpack(pack_format, packet)
        pack_format = "!" + "B"*len(packet)
        granted_qos = struct.unpack(pack_format, packet)

        s = "SUBACK, rl="+str(rl)+", mid="+str(mid)+", granted_qos="+str(granted_qos[0])
        for i in range(1, len(granted_qos)-1):
            s = s+", "+str(granted_qos[i])
        return s
    elif cmd == 0xA0:
        # UNSUBSCRIBE
        (packet, rl) = remaining_length(packet)
        pack_format = "!H" + str(len(packet)-2) + 's'
        (mid, packet) = struct.unpack(pack_format, packet)
        s = "UNSUBSCRIBE, rl="+str(rl)+", mid="+str(mid)
        topic_index = 0
        while len(packet) > 0:
            pack_format = "!H" + str(len(packet)-2) + 's'
            (tlen, packet) = struct.unpack(pack_format, packet)
            pack_format = "!" + str(tlen)+'s' + str(len(packet)-tlen) + 's'
            (topic, packet) = struct.unpack(pack_format, packet)
            s = s + ", topic"+str(topic_index)+"="+str(topic)
        return s
    elif cmd == 0xB0:
        # UNSUBACK
        (cmd, rl, mid) = struct.unpack('!BBH', packet)
        return "UNSUBACK, rl="+str(rl)+", mid="+str(mid)
    elif cmd == 0xC0:
        # PINGREQ
        (cmd, rl) = struct.unpack('!BB', packet)
        return "PINGREQ, rl="+str(rl)
    elif cmd == 0xD0:
        # PINGRESP
        (cmd, rl) = struct.unpack('!BB', packet)
        return "PINGRESP, rl="+str(rl)
    elif cmd == 0xE0:
        # DISCONNECT
        (cmd, rl) = struct.unpack('!BB', packet)
        return "DISCONNECT, rl="+str(rl)
    elif cmd == 0xF0:
        # AUTH
        (cmd, rl) = struct.unpack('!BB', packet)
        return "AUTH, rl="+str(rl)


def read_varint(sock, rl):
    varint = 0
    multiplier = 1
    while True:
        byte = sock.recv(1)
        byte, = struct.unpack("!B", byte)
        varint += (byte & 127)*multiplier
        multiplier *= 128
        rl -= 1
        if byte & 128 == 0x00:
            return (varint, rl)


def mqtt_read_string(sock, rl):
    slen = sock.recv(2)
    slen, = struct.unpack("!H", slen)
    payload = sock.recv(slen)
    payload, = struct.unpack("!%ds" % (slen), payload)
    rl -= (2 + slen)
    return (payload, rl)


def read_publish(sock, proto_ver=4):
    cmd, = struct.unpack("!B", sock.recv(1))
    if cmd & 0xF0 != 0x30:
        raise ValueError

    qos = (cmd & 0x06) >> 1
    rl, t = read_varint(sock, 0)
    topic, rl = mqtt_read_string(sock, rl)

    if qos > 0:
        sock.recv(2)
        rl -= 1

    if proto_ver == 5:
        proplen, rl = read_varint(sock, rl)
        sock.recv(proplen)
        rl -= proplen

    payload = sock.recv(rl).decode('utf-8')
    return payload


def gen_connect(client_id, clean_session=True, keepalive=60, username=None, password=None, will_topic=None, will_qos=0, will_retain=False, will_payload=b"", proto_ver=4, connect_reserved=False, properties=b"", will_properties=b"", session_expiry=-1):
    if (proto_ver&0x7F) == 3 or proto_ver == 0:
        remaining_length = 12
    elif (proto_ver&0x7F) == 4 or proto_ver == 5:
        remaining_length = 10
    else:
        raise ValueError

    if client_id != None:
        client_id = client_id.encode("utf-8")
        remaining_length = remaining_length + 2+len(client_id)
    else:
        remaining_length = remaining_length + 2

    connect_flags = 0

    if connect_reserved:
        connect_flags = connect_flags | 0x01

    if clean_session:
        connect_flags = connect_flags | 0x02

    if proto_ver == 5:
        if properties == b"":
            properties += mqtt5_props.gen_uint16_prop(mqtt5_props.PROP_RECEIVE_MAXIMUM, 20)

        if session_expiry != -1:
            properties += mqtt5_props.gen_uint32_prop(mqtt5_props.PROP_SESSION_EXPIRY_INTERVAL, session_expiry)

        properties = mqtt5_props.prop_finalise(properties)
        remaining_length += len(properties)

    if will_topic != None:
        will_topic = will_topic.encode("utf-8")
        remaining_length = remaining_length + 2+len(will_topic) + 2+len(will_payload)
        connect_flags = connect_flags | 0x04 | ((will_qos&0x03) << 3)
        if will_retain:
            connect_flags = connect_flags | 32
        if proto_ver == 5:
            will_properties = mqtt5_props.prop_finalise(will_properties)
            remaining_length += len(will_properties)

    if username != None:
        username = username.encode("utf-8")
        remaining_length = remaining_length + 2+len(username)
        connect_flags = connect_flags | 0x80
        if password != None:
            password = password.encode("utf-8")
            connect_flags = connect_flags | 0x40
            remaining_length = remaining_length + 2+len(password)

    rl = pack_remaining_length(remaining_length)
    packet = struct.pack("!B"+str(len(rl))+"s", 0x10, rl)
    if (proto_ver&0x7F) == 3 or proto_ver == 0:
        packet = packet + struct.pack("!H6sBBH", len(b"MQIsdp"), b"MQIsdp", proto_ver, connect_flags, keepalive)
    elif (proto_ver&0x7F) == 4 or proto_ver == 5:
        packet = packet + struct.pack("!H4sBBH", len(b"MQTT"), b"MQTT", proto_ver, connect_flags, keepalive)

    if proto_ver == 5:
        packet += properties

    if client_id != None:
        packet = packet + struct.pack("!H"+str(len(client_id))+"s", len(client_id), bytes(client_id))
    else:
        packet = packet + struct.pack("!H", 0)

    if will_topic != None:
        packet += will_properties
        packet = packet + struct.pack("!H"+str(len(will_topic))+"s", len(will_topic), will_topic)
        if len(will_payload) > 0:
            packet = packet + struct.pack("!H"+str(len(will_payload))+"s", len(will_payload), will_payload)
        else:
            packet = packet + struct.pack("!H", 0)

    if username != None:
        packet = packet + struct.pack("!H"+str(len(username))+"s", len(username), username)
        if password != None:
            packet = packet + struct.pack("!H"+str(len(password))+"s", len(password), password)
    return packet

def gen_connack(flags=0, rc=0, proto_ver=4, properties=b"", property_helper=True):
    if proto_ver == 5:
        if property_helper == True:
            if properties is not None:
                properties = mqtt5_props.gen_uint16_prop(mqtt5_props.PROP_TOPIC_ALIAS_MAXIMUM, 10) \
                    + properties + mqtt5_props.gen_uint16_prop(mqtt5_props.PROP_RECEIVE_MAXIMUM, 20)
            else:
                properties = b""
        properties = mqtt5_props.prop_finalise(properties)

        packet = struct.pack('!BBBB', 32, 2+len(properties), flags, rc) + properties
    else:
        packet = struct.pack('!BBBB', 32, 2, flags, rc);

    return packet

def gen_publish(topic, qos, payload=None, retain=False, dup=False, mid=0, proto_ver=4, properties=b""):
    topic = topic.encode("utf-8")
    rl = 2+len(topic)
    pack_format = "H"+str(len(topic))+"s"
    if qos > 0:
        rl = rl + 2
        pack_format = pack_format + "H"

    if proto_ver == 5:
        properties = mqtt5_props.prop_finalise(properties)
        rl += len(properties)
        # This will break if len(properties) > 127
        pack_format = pack_format + "%ds"%(len(properties))

    if payload != None:
        payload = payload.encode("utf-8")
        rl = rl + len(payload)
        pack_format = pack_format + str(len(payload))+"s"
    else:
        payload = b""
        pack_format = pack_format + "0s"

    rlpacked = pack_remaining_length(rl)
    cmd = 48 | (qos<<1)
    if retain:
        cmd = cmd + 1
    if dup:
        cmd = cmd + 8

    if proto_ver == 5:
        if qos > 0:
            return struct.pack("!B" + str(len(rlpacked))+"s" + pack_format, cmd, rlpacked, len(topic), topic, mid, properties, payload)
        else:
            return struct.pack("!B" + str(len(rlpacked))+"s" + pack_format, cmd, rlpacked, len(topic), topic, properties, payload)
    else:
        if qos > 0:
            return struct.pack("!B" + str(len(rlpacked))+"s" + pack_format, cmd, rlpacked, len(topic), topic, mid, payload)
        else:
            return struct.pack("!B" + str(len(rlpacked))+"s" + pack_format, cmd, rlpacked, len(topic), topic, payload)

def _gen_command_with_mid(cmd, mid, proto_ver=4, reason_code=-1, properties=None):
    if proto_ver == 5 and (reason_code != -1 or properties is not None):
        if reason_code == -1:
            reason_code = 0

        if properties is None:
            return struct.pack('!BBHB', cmd, 3, mid, reason_code)
        elif properties == "":
            return struct.pack('!BBHBB', cmd, 4, mid, reason_code, 0)
        else:
            properties = mqtt5_props.prop_finalise(properties)
            pack_format = "!BBHB"+str(len(properties))+"s"
            return struct.pack(pack_format, cmd, 2+1+len(properties), mid, reason_code, properties)
    else:
        return struct.pack('!BBH', cmd, 2, mid)

def gen_puback(mid, proto_ver=4, reason_code=-1, properties=None):
    return _gen_command_with_mid(64, mid, proto_ver, reason_code, properties)

def gen_pubrec(mid, proto_ver=4, reason_code=-1, properties=None):
    return _gen_command_with_mid(80, mid, proto_ver, reason_code, properties)

def gen_pubrel(mid, dup=False, proto_ver=4, reason_code=-1, properties=None):
    if dup:
        cmd = 96+8+2
    else:
        cmd = 96+2
    return _gen_command_with_mid(cmd, mid, proto_ver, reason_code, properties)

def gen_pubcomp(mid, proto_ver=4, reason_code=-1, properties=None):
    return _gen_command_with_mid(112, mid, proto_ver, reason_code, properties)


def gen_subscribe(mid, topic, qos, cmd=130, proto_ver=4, properties=b""):
    topic = topic.encode("utf-8")
    packet = struct.pack("!B", cmd)
    if proto_ver == 5:
        if properties == b"":
            packet += pack_remaining_length(2+1+2+len(topic)+1)
            pack_format = "!HBH"+str(len(topic))+"sB"
            return packet + struct.pack(pack_format, mid, 0, len(topic), topic, qos)
        else:
            properties = mqtt5_props.prop_finalise(properties)
            packet += pack_remaining_length(2+1+2+len(topic)+len(properties))
            pack_format = "!H"+str(len(properties))+"s"+"H"+str(len(topic))+"sB"
            return packet + struct.pack(pack_format, mid, properties, len(topic), topic, qos)
    else:
        packet += pack_remaining_length(2+2+len(topic)+1)
        pack_format = "!HH"+str(len(topic))+"sB"
        return packet + struct.pack(pack_format, mid, len(topic), topic, qos)


def gen_suback(mid, qos, proto_ver=4):
    if proto_ver == 5:
        return struct.pack('!BBHBB', 144, 2+1+1, mid, 0, qos)
    else:
        return struct.pack('!BBHB', 144, 2+1, mid, qos)

def gen_unsubscribe(mid, topic, cmd=162, proto_ver=4, properties=b""):
    topic = topic.encode("utf-8")
    if proto_ver == 5:
        if properties == b"":
            pack_format = "!BBHBH"+str(len(topic))+"s"
            return struct.pack(pack_format, cmd, 2+2+len(topic)+1, mid, 0, len(topic), topic)
        else:
            properties = mqtt5_props.prop_finalise(properties)
            packet = struct.pack("!B", cmd)
            l = 2+2+len(topic)+1+len(properties)
            packet += pack_remaining_length(l)
            pack_format = "!HB"+str(len(properties))+"sH"+str(len(topic))+"s"
            packet += struct.pack(pack_format, mid, len(properties), properties, len(topic), topic)
            return packet
    else:
        pack_format = "!BBHH"+str(len(topic))+"s"
        return struct.pack(pack_format, cmd, 2+2+len(topic), mid, len(topic), topic)

def gen_unsubscribe_multiple(mid, topics, proto_ver=4):
    packet = b""
    remaining_length = 0
    for t in topics:
        t = t.encode("utf-8")
        remaining_length += 2+len(t)
        packet += struct.pack("!H"+str(len(t))+"s", len(t), t)

    if proto_ver == 5:
        remaining_length += 2+1

        return struct.pack("!BBHB", 162, remaining_length, mid, 0) + packet
    else:
        remaining_length += 2

        return struct.pack("!BBH", 162, remaining_length, mid) + packet

def gen_unsuback(mid, reason_code=0, proto_ver=4):
    if proto_ver == 5:
        if isinstance(reason_code, list):
            reason_code_count = len(reason_code)
            p = struct.pack('!BBHB', 176, 3+reason_code_count, mid, 0)
            for r in reason_code:
                p += struct.pack('B', r)
            return p
        else:
            return struct.pack('!BBHBB', 176, 4, mid, 0, reason_code)
    else:
        return struct.pack('!BBH', 176, 2, mid)

def gen_pingreq():
    return struct.pack('!BB', 192, 0)

def gen_pingresp():
    return struct.pack('!BB', 208, 0)


def _gen_short(cmd, reason_code=-1, proto_ver=5, properties=None):
    if proto_ver == 5 and (reason_code != -1 or properties is not None):
        if reason_code == -1:
             reason_code = 0

        if properties is None:
            return struct.pack('!BBB', cmd, 1, reason_code)
        elif properties == "":
            return struct.pack('!BBBB', cmd, 2, reason_code, 0)
        else:
            properties = mqtt5_props.prop_finalise(properties)
            return struct.pack("!BBB", cmd, 1+len(properties), reason_code) + properties
    else:
        return struct.pack('!BB', cmd, 0)

def gen_disconnect(reason_code=-1, proto_ver=4, properties=None):
    return _gen_short(0xE0, reason_code, proto_ver, properties)

def gen_auth(reason_code=-1, properties=None):
    return _gen_short(0xF0, reason_code, 5, properties)


def pack_remaining_length(remaining_length):
    s = b""
    while True:
        byte = remaining_length % 128
        remaining_length = remaining_length // 128
        # If there are more digits to encode, set the top bit of this digit
        if remaining_length > 0:
            byte = byte | 0x80

        s = s + struct.pack("!B", byte)
        if remaining_length == 0:
            return s


def get_port(count=1):
    if count == 1:
        if len(sys.argv) == 2:
            return int(sys.argv[1])
        else:
            return 1888
    else:
        if len(sys.argv) == 1+count:
            p = ()
            for i in range(0, count):
                p = p + (int(sys.argv[1+i]),)
            return p
        else:
            return tuple(range(1888, 1888+count))


def get_lib_port():
    if len(sys.argv) == 3:
        return int(sys.argv[2])
    else:
        return 1888


def do_ping(sock, error_string="pingresp"):
     do_send_receive(sock, gen_pingreq(), gen_pingresp(), error_string)


@atexit.register
def test_cleanup():
    global vg_logfiles

    if os.environ.get('MOSQ_USE_VALGRIND') is not None:
        for f in vg_logfiles:
            try:
                if os.stat(f).st_size == 0:
                    os.remove(f)
            except OSError:
                pass
