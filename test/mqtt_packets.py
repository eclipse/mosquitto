import struct
import mqtt5_props


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


def _pack_remaining_length(remaining_length):
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
            properties += mqtt5_props.gen_uint16_prop(mqtt5_props.RECEIVE_MAXIMUM, 20)

        if session_expiry != -1:
            properties += mqtt5_props.gen_uint32_prop(mqtt5_props.SESSION_EXPIRY_INTERVAL, session_expiry)

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

    rl = _pack_remaining_length(remaining_length)
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
                properties = mqtt5_props.gen_uint16_prop(mqtt5_props.TOPIC_ALIAS_MAXIMUM, 10) \
                    + properties \
                    + mqtt5_props.gen_uint32_prop(mqtt5_props.MAXIMUM_PACKET_SIZE, 2000000) \
                    + mqtt5_props.gen_uint16_prop(mqtt5_props.RECEIVE_MAXIMUM, 20)
            else:
                properties = b""
        properties = mqtt5_props.prop_finalise(properties)

        packet = struct.pack('!BBBB', 0x20, 2+len(properties), flags, rc) + properties
    else:
        packet = struct.pack('!BBBB', 0x20, 2, flags, rc);

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
        if isinstance(payload, bytes) == False:
            payload = payload.encode("utf-8")
        rl = rl + len(payload)
        pack_format = pack_format + str(len(payload))+"s"
    else:
        payload = b""
        pack_format = pack_format + "0s"

    rlpacked = _pack_remaining_length(rl)
    cmd = 0x30 | (qos<<1)
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


def gen_puback(mid, proto_ver=4, reason_code=-1, properties=None):
    return _gen_command_with_mid(64, mid, proto_ver, reason_code, properties)


def gen_pubrec(mid, proto_ver=4, reason_code=-1, properties=None):
    return _gen_command_with_mid(80, mid, proto_ver, reason_code, properties)


def gen_pubrel(mid, dup=False, proto_ver=4, reason_code=-1, properties=None):
    cmd = 0x60 | 0x02
    if dup:
        cmd = cmd | 0x08
    return _gen_command_with_mid(cmd, mid, proto_ver, reason_code, properties)


def gen_pubcomp(mid, proto_ver=4, reason_code=-1, properties=None):
    return _gen_command_with_mid(112, mid, proto_ver, reason_code, properties)


def gen_subscribe(mid, topic, qos, cmd=0x82, proto_ver=4, properties=b""):
    topic = topic.encode("utf-8")
    packet = struct.pack("!B", cmd)
    if proto_ver == 5:
        if properties == b"":
            packet += _pack_remaining_length(2+1+2+len(topic)+1)
            pack_format = "!HBH"+str(len(topic))+"sB"
            return packet + struct.pack(pack_format, mid, 0, len(topic), topic, qos)
        else:
            properties = mqtt5_props.prop_finalise(properties)
            packet += _pack_remaining_length(2+1+2+len(topic)+len(properties))
            pack_format = "!H"+str(len(properties))+"s"+"H"+str(len(topic))+"sB"
            return packet + struct.pack(pack_format, mid, properties, len(topic), topic, qos)
    else:
        packet += _pack_remaining_length(2+2+len(topic)+1)
        pack_format = "!HH"+str(len(topic))+"sB"
        return packet + struct.pack(pack_format, mid, len(topic), topic, qos)


def gen_suback(mid, qos, proto_ver=4):
    if proto_ver == 5:
        return struct.pack('!BBHBB', 0x90, 2+1+1, mid, 0, qos)
    else:
        return struct.pack('!BBHB', 0x90, 2+1, mid, qos)


def gen_unsubscribe(mid, topic, cmd=0xA2, proto_ver=4, properties=b""):
    topic = topic.encode("utf-8")
    if proto_ver == 5:
        if properties == b"":
            pack_format = "!BBHBH"+str(len(topic))+"s"
            return struct.pack(pack_format, cmd, 2+2+len(topic)+1, mid, 0, len(topic), topic)
        else:
            properties = mqtt5_props.prop_finalise(properties)
            packet = struct.pack("!B", cmd)
            l = 2+2+len(topic)+len(properties)
            packet += _pack_remaining_length(l)
            pack_format = "!H"+str(len(properties))+"sH"+str(len(topic))+"s"
            packet += struct.pack(pack_format, mid, properties, len(topic), topic)
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

        return struct.pack("!BBHB", 0xA2, remaining_length, mid, 0) + packet
    else:
        remaining_length += 2

        return struct.pack("!BBH", 0xA2, remaining_length, mid) + packet


def gen_unsuback(mid, reason_code=0, proto_ver=4):
    if proto_ver == 5:
        if isinstance(reason_code, list):
            reason_code_count = len(reason_code)
            p = struct.pack('!BBHB', 0xB0, 3+reason_code_count, mid, 0)
            for r in reason_code:
                p += struct.pack('B', r)
            return p
        else:
            return struct.pack('!BBHBB', 0xB0, 4, mid, 0, reason_code)
    else:
        return struct.pack('!BBH', 0xB0, 2, mid)


def gen_pingreq():
    return struct.pack('!BB', 0xC0, 0)


def gen_pingresp():
    return struct.pack('!BB', 0xD0, 0)


def gen_disconnect(reason_code=-1, proto_ver=4, properties=None):
    return _gen_short(0xE0, reason_code, proto_ver, properties)


def gen_auth(reason_code=-1, properties=None):
    return _gen_short(0xF0, reason_code, 5, properties)
