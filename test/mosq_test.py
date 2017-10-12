import errno
import os
import socket
import subprocess
import struct
import time

def start_broker(filename, cmd=None, port=1888):
    delay = 0.1
    if cmd is None:
        cmd = ['../../src/mosquitto', '-v', '-c', filename.replace('.py', '.conf')]
    if os.environ.get('MOSQ_USE_VALGRIND') is not None:
        cmd = ['valgrind', '--trace-children=yes', '-v', '--log-file='+filename+'.vglog'] + cmd
        delay = 1

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
    raise IOError

def start_client(filename, cmd, env):
    if cmd is None:
        raise ValueError
    if os.environ.get('MOSQ_USE_VALGRIND') is not None:
        cmd = ['valgrind', '-q', '--log-file='+filename+'.vglog'] + cmd

    return subprocess.Popen(cmd, env=env)

def expect_packet(sock, name, expected):
    if len(expected) > 0:
        rlen = len(expected)
    else:
        rlen = 1

    packet_recvd = sock.recv(rlen)
    return packet_matches(name, packet_recvd, expected)

def packet_matches(name, recvd, expected):
    if recvd != expected:
        print("FAIL: Received incorrect "+name+".")
        try:
            print("Received: "+to_string(recvd))
        except struct.error:
            print("Received (not decoded): "+recvd)
        try:
            print("Expected: "+to_string(expected))
        except struct.error:
            print("Expected (not decoded): "+expected)

        return 0
    else:
        return 1

def do_client_connect(connect_packet, connack_packet, hostname="localhost", port=1888, timeout=60, connack_error="connack"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((hostname, port))
    sock.send(connect_packet)

    if expect_packet(sock, connack_error, connack_packet):
        return sock
    else:
        sock.close()
        raise ValueError

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

    packet0 = struct.unpack("!B", packet[0])
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
        s = "CONNECT, proto="+protocol+str(proto_ver)+", keepalive="+str(keepalive)
        if flags&2:
            s = s+", clean-session"
        else:
            s = s+", durable"

        pack_format = "!H" + str(len(packet)-2) + 's'
        (slen, packet) = struct.unpack(pack_format, packet)
        pack_format = "!" + str(slen)+'s' + str(len(packet)-slen) + 's'
        (client_id, packet) = struct.unpack(pack_format, packet)
        s = s+", id="+client_id

        if flags&4:
            pack_format = "!H" + str(len(packet)-2) + 's'
            (slen, packet) = struct.unpack(pack_format, packet)
            pack_format = "!" + str(slen)+'s' + str(len(packet)-slen) + 's'
            (will_topic, packet) = struct.unpack(pack_format, packet)
            s = s+", will-topic="+will_topic

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
            s = s+", username="+username

        if flags&64:
            pack_format = "!H" + str(len(packet)-2) + 's'
            (slen, packet) = struct.unpack(pack_format, packet)
            pack_format = "!" + str(slen)+'s' + str(len(packet)-slen) + 's'
            (password, packet) = struct.unpack(pack_format, packet)
            s = s+", password="+password

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
        s = "PUBLISH, rl="+str(rl)+", topic="+topic+", qos="+str(qos)+", retain="+str(retain)+", dup="+str(dup)
        if qos > 0:
            pack_format = "!H" + str(len(packet)-2) + 's'
            (mid, packet) = struct.unpack(pack_format, packet)
            s = s + ", mid="+str(mid)

        s = s + ", payload="+packet
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
            s = s + ", topic"+str(topic_index)+"="+topic+","+str(qos)
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
            s = s + ", topic"+str(topic_index)+"="+topic
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
        # Reserved
        return "0xF0"

def gen_connect(client_id, clean_session=True, keepalive=60, username=None, password=None, will_topic=None, will_qos=0, will_retain=False, will_payload="", proto_ver=3, connect_reserved=False):
    if (proto_ver&0x7F) == 3 or proto_ver == 0:
        remaining_length = 12
    elif (proto_ver&0x7F) == 4:
        remaining_length = 10
    else:
        raise ValueError

    if client_id != None:
        remaining_length = remaining_length + 2+len(client_id)

    connect_flags = 0

    if connect_reserved:
        connect_flags = connect_flags | 0x01

    if clean_session:
        connect_flags = connect_flags | 0x02

    if will_topic != None:
        remaining_length = remaining_length + 2+len(will_topic) + 2+len(will_payload)
        connect_flags = connect_flags | 0x04 | ((will_qos&0x03) << 3)
        if will_retain:
            connect_flags = connect_flags | 32

    if username != None:
        remaining_length = remaining_length + 2+len(username)
        connect_flags = connect_flags | 0x80
        if password != None:
            connect_flags = connect_flags | 0x40
            remaining_length = remaining_length + 2+len(password)

    rl = pack_remaining_length(remaining_length)
    packet = struct.pack("!B"+str(len(rl))+"s", 0x10, rl)
    if (proto_ver&0x7F) == 3 or proto_ver == 0:
        packet = packet + struct.pack("!H6sBBH", len("MQIsdp"), "MQIsdp", proto_ver, connect_flags, keepalive)
    elif (proto_ver&0x7F) == 4:
        packet = packet + struct.pack("!H4sBBH", len("MQTT"), "MQTT", proto_ver, connect_flags, keepalive)

    if client_id != None:
        packet = packet + struct.pack("!H"+str(len(client_id))+"s", len(client_id), client_id)

    if will_topic != None:
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

def gen_connack(resv=0, rc=0):
    return struct.pack('!BBBB', 32, 2, resv, rc);

def gen_publish(topic, qos, payload=None, retain=False, dup=False, mid=0):
    rl = 2+len(topic)
    pack_format = "!BBH"+str(len(topic))+"s"
    if qos > 0:
        rl = rl + 2
        pack_format = pack_format + "H"
    if payload != None:
        rl = rl + len(payload)
        pack_format = pack_format + str(len(payload))+"s"
    else:
        payload = ""
        pack_format = pack_format + "0s"

    cmd = 48 | (qos<<1)
    if retain:
        cmd = cmd + 1
    if dup:
        cmd = cmd + 8

    if qos > 0:
        return struct.pack(pack_format, cmd, rl, len(topic), topic, mid, payload)
    else:
        return struct.pack(pack_format, cmd, rl, len(topic), topic, payload)

def gen_puback(mid):
    return struct.pack('!BBH', 64, 2, mid)

def gen_pubrec(mid):
    return struct.pack('!BBH', 80, 2, mid)

def gen_pubrel(mid, dup=False):
    if dup:
        cmd = 96+8+2
    else:
        cmd = 96+2
    return struct.pack('!BBH', cmd, 2, mid)

def gen_pubcomp(mid):
    return struct.pack('!BBH', 112, 2, mid)

def gen_subscribe(mid, topic, qos):
    pack_format = "!BBHH"+str(len(topic))+"sB"
    return struct.pack(pack_format, 130, 2+2+len(topic)+1, mid, len(topic), topic, qos)

def gen_suback(mid, qos):
    return struct.pack('!BBHB', 144, 2+1, mid, qos)

def gen_unsubscribe(mid, topic):
    pack_format = "!BBHH"+str(len(topic))+"s"
    return struct.pack(pack_format, 162, 2+2+len(topic), mid, len(topic), topic)

def gen_unsuback(mid):
    return struct.pack('!BBH', 176, 2, mid)

def gen_pingreq():
    return struct.pack('!BB', 192, 0)

def gen_pingresp():
    return struct.pack('!BB', 208, 0)

def gen_disconnect():
    return struct.pack('!BB', 224, 0)

def pack_remaining_length(remaining_length):
    s = ""
    while True:
        byte = remaining_length % 128
        remaining_length = remaining_length // 128
        # If there are more digits to encode, set the top bit of this digit
        if remaining_length > 0:
            byte = byte | 0x80

        s = s + struct.pack("!B", byte)
        if remaining_length == 0:
            return s
