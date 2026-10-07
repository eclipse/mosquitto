import atexit
import base64
import errno
import hashlib
import os
import platform
import signal
import socket
import ssl
import subprocess
import struct
import sys
import tempfile
import time
import uuid
import traceback
from functools import wraps

import mqtt_packets
import mqtt5_props

if platform.system() == "Windows":
    import win32event

import __main__

from pathlib import Path
vg_index = 1
vg_logfiles = []

class TestError(Exception):
    def __init__(self, message="Mismatched packets"):
        self.message = message


def retry(retries=5, delay=1):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    print(f"Retrying {func.__name__} {attempt+1}/{retries}")
                    last_exception = e
                    if attempt < retries - 1:
                        time.sleep(delay)
            raise last_exception
        return wrapper
    return decorator


def get_build_root():
    result = os.getenv("BUILD_ROOT")
    if result is None:
        result = str(Path(__file__).resolve().parents[1])
    return result

def get_build_type():
    if platform.system() == 'Windows':
        buildtype = os.environ.get('CMAKE_CONFIG_TYPE')
        if buildtype is None:
            buildtype = 'RelWithDebInfo'
    else:
        buildtype = ''
    return buildtype

def env_add_ld_library_path(env=None, extra_path=""):
    if platform.system() == 'Windows':
        pathsep = ';'
        pathvar = 'PATH'
    elif platform.system() == 'Darwin':
        pathsep = ':'
        pathvar = 'DYLIB_LIBRARY_PATH'
    else:
        pathsep = ':'
        pathvar = 'LD_LIBRARY_PATH'

    p = pathsep.join([
        str(Path(get_build_root(), 'libcommon', get_build_type())),
        str(Path(get_build_root(), 'lib', get_build_type())),
        str(Path(get_build_root(), 'lib', 'cpp', get_build_type())),
        extra_path,
        os.getenv(pathvar, "")
    ])

    newenv = os.environ.copy()
    if env is not None:
        for key, value in env.items():
            newenv[key] = value

    newenv[pathvar] = p

    return newenv

def listen_sock(port, cafile=None, certfile=None, keyfile=None, cert_required=False, timeout=5):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    if cafile is not None:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=cafile)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        if cert_required:
            context.verify_mode = ssl.CERT_REQUIRED
        sock = context.wrap_socket(sock, server_side=True)
    sock.settimeout(timeout)
    sock.bind(('', port))
    sock.listen(5)
    return sock

def broker_log(broker):
    try:
        broker.mosq_log.seek(0)
        return broker.mosq_log.read().decode('utf-8')
    except AttributeError:
        return None

def start_broker(filename, cmd=None, port=0, use_conf=False, expect_fail=False, expect_fail_log=None, nolog=False, checkhost="localhost", env=None, check_port=True, cmd_args=None, timeout=0.1):
    global vg_index
    global vg_logfiles

    broker_path = Path(get_build_root(), 'src', get_build_type(), 'mosquitto')

    if use_conf == True:
        cmd = [broker_path, '-v', '-c', filename.replace('.py', '.conf')]

        if port == 0:
            port = 1888
        else:
            cmd += ['-p', str(port)]
    else:
        if cmd is None and port != 0:
            cmd = [broker_path, '-v', '-p', str(port)]
        elif cmd is None and port == 0:
            cmd = [broker_path, '-v', '-c', filename.replace('.py', '.conf')]

    if os.environ.get('MOSQ_USE_VALGRIND') is not None:
        logfile = filename+'.'+str(vg_index)+'.vglog'
        if os.environ.get('MOSQ_USE_VALGRIND') == 'callgrind':
            cmd = ['valgrind', '-q', '--tool=callgrind', '--log-file='+logfile] + cmd
        elif os.environ.get('MOSQ_USE_VALGRIND') == 'massif':
            cmd = ['valgrind', '-q', '--tool=massif', '--log-file='+logfile] + cmd
        elif os.environ.get('MOSQ_USE_VALGRIND') == 'failgrind':
            cmd = ['fg-helper'] + cmd
        else:
            cmd = ['valgrind', '-q', '--gen-suppressions=all', '--suppressions=test.supp', '--track-fds=yes', '--trace-children=yes', '--leak-check=full', '--show-leak-kinds=all', '--log-file='+logfile] + cmd
        vg_logfiles.append(logfile)
        vg_index += 1
        timeout = 1

    if cmd_args:
        cmd.extend(cmd_args)

    stderr = tempfile.TemporaryFile(prefix=str(port), suffix=".log")

    env = env_add_ld_library_path(env)
    broker = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=stderr, env=env)
    broker.mosq_log = stderr

    if expect_fail:
        try:
            broker.wait(timeout*10)
            if expect_fail_log is not None:
                stde = broker_log(broker)
                if expect_fail_log not in stde:
                    print(f"{expect_fail_log} not found in log.")
                    print(stde.decode('utf-8'))
                    raise ValueError()
        except subprocess.TimeoutExpired:
            _, errs = terminate_broker(broker)
            print(f"Broker did not fail to start:\n{errs}")
            raise
        return broker

    if check_port == False:
        return broker

    assert port != 0

    for i in range(0, 20):
        time.sleep(timeout)
        c = None
        try:
            c = socket.create_connection((checkhost, port))
        except socket.error as err:
            if err.errno != errno.ECONNREFUSED:
                raise

        if c is not None:
            c.close()
            return broker

    if expect_fail == False:
        stde = broker_log(broker)
        print(f"FAIL: unable to start broker: {stde}")
        raise IOError
    else:
        return broker

def start_client(filename, cmd, env=None):
    if cmd is None:
        raise ValueError
    env = env_add_ld_library_path(env)
    if os.environ.get('MOSQ_USE_VALGRIND') is not None:
        cmd = ['valgrind', '-q', '--log-file='+filename+'.vglog'] + cmd

    return subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

def wait_for_subprocess(client,timeout=10,terminate_timeout=2):
    rc=0
    try:
        client.wait(timeout)
    except subprocess.TimeoutExpired:
        rc=1
        client.terminate()
        try:
            client.wait(terminate_timeout)
        except subprocess.TimeoutExpired:
            rc=2
            client.kill()
            try:
                client.wait(terminate_timeout)
            except subprocess.TimeoutExpired:
                rc=3
                pass
    return rc


def terminate_broker(broker, force=False):
    if platform.system() == 'Windows' and force == False:
        evt_sent = False
        for i in range(5):
            try:
                evt = win32event.OpenEvent(win32event.EVENT_ALL_ACCESS, False, f"mosq{broker.pid}_shutdown")
                win32event.PulseEvent(evt)
                evt_sent = True
                break
            except Exception:
                time.sleep(0.5)
        if evt_sent == False:
            broker.terminate()
    else:
        broker.terminate()
    stde = broker_log(broker)
    if wait_for_subprocess(broker):
        print("broker not terminated")
        return (1, stde)
    else:
        return (0, stde)

def reload_broker(broker):
    if platform.system() == 'Windows':
        for i in range(10):
            try:
                evt = win32event.OpenEvent(win32event.EVENT_ALL_ACCESS, False, f"mosq{broker.pid}_reload")
                win32event.SetEvent(evt)
                return
            except Exception as e:
                time.sleep(0.5)
                print(e)
                pass
    else:
        broker.send_signal(signal.SIGHUP)

def pub_helper(port, proto_ver=4):
    connect_packet = mqtt_packets.gen_connect("pub-helper", proto_ver=proto_ver)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    sock = do_client_connect(connect_packet, connack_packet, port=port, connack_error="pub helper connack")
    return sock


def sub_helper(port, topic='#', qos=0, proto_ver=4):
    connect_packet = mqtt_packets.gen_connect("sub-helper", proto_ver=proto_ver)
    connack_packet = mqtt_packets.gen_connack(rc=0, proto_ver=proto_ver)

    mid = 1
    subscribe_packet = mqtt_packets.gen_subscribe(mid=mid, topic=topic, qos=qos, proto_ver=proto_ver)
    suback_packet = mqtt_packets.gen_suback(mid=mid, qos=qos, proto_ver=proto_ver)
    sock = do_client_connect(connect_packet, connack_packet, port=port)
    do_send_receive(sock, subscribe_packet, suback_packet, "sub helper suback")
    return sock


def expect_packet(sock, name, expected):
    if len(expected) > 0:
        rlen = len(expected)
    else:
        rlen = 1

    packet_recvd = b""
    try:
        while len(packet_recvd) < rlen:
            data = sock.recv(rlen-len(packet_recvd))
            if len(data) == 0:
                try:
                    s = f"when reading {name} from {sock.getpeername()}"
                except OSError:
                    s = f"when reading {name} from {sock}"
                raise BrokenPipeError(s)
            packet_recvd += data
    except socket.timeout:
        pass

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
        traceback.print_stack(file=sys.stdout)

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


def do_send(sock, send_packet):
    size = len(send_packet)
    total_sent = 0
    while total_sent < size:
        sent = sock.send(send_packet[total_sent:])
        if sent == 0:
            raise RuntimeError("socket connection broken")
        total_sent += sent

def do_send_receive(sock, send_packet, receive_packet, error_string="send receive error"):
    do_send(sock, send_packet)

    if expect_packet(sock, error_string, receive_packet):
        return sock
    else:
        sock.close()
        raise ValueError


# Useful for mocking a client receiving (with ack) a qos1 publish
def do_receive_send(sock, receive_packet, send_packet, error_string="receive send error"):
    if expect_packet(sock, error_string, receive_packet):
        do_send(sock, send_packet)
        return sock
    else:
        sock.close()
        raise ValueError


def client_connect_only(hostname="localhost", port=1888, timeout=10, protocol="mqtt"):
    if protocol == "websockets":
        addr = (hostname, port)
        sock = socket.create_connection(addr, timeout=timeout)
        sock.settimeout(timeout)
        sock = WebsocketWrapper(sock, hostname, port, False, "/mqtt", None)
        #sock.setblocking(0)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((hostname, port))
    return sock

def client_connect_only_unix(path, timeout=10):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect(path)
    return sock

def do_client_connect(connect_packet, connack_packet, hostname="localhost", port=1888, timeout=10, connack_error="connack", protocol="mqtt"):
    sock = client_connect_only(hostname, port, timeout, protocol)

    return do_send_receive(sock, connect_packet, connack_packet, connack_error)


def do_client_connect_unix(connect_packet, connack_packet, path, timeout=10, connack_error="connack"):
    sock = client_connect_only_unix(path, timeout)

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
            s = s+", will-message="+str(will_message)

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
        if len(packet) >= 4:
            (cmd, rl, flags, reason_code) = struct.unpack('!BBBB', packet[0:4])
            s=f"CONNACK, rl={rl}, res/flags={flags}, rc={reason_code}"
            if len(packet) > 4:
                s = s+ f", properties={mqtt5_props.print_properties(packet[4:])}"
            return s
        else:
            return "CONNACK, (not decoded)"

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
        if len(packet) == 5:
            (cmd, rl, mid, reason_code) = struct.unpack('!BBHB', packet)
            return "PUBACK, rl="+str(rl)+", mid="+str(mid)+", reason_code="+str(reason_code)
        else:
            (cmd, rl, mid) = struct.unpack('!BBH', packet)
            return "PUBACK, rl="+str(rl)+", mid="+str(mid)
    elif cmd == 0x50:
        # PUBREC
        if len(packet) == 5:
            (cmd, rl, mid, reason_code) = struct.unpack('!BBHB', packet)
            return "PUBREC, rl="+str(rl)+", mid="+str(mid)+", reason_code="+str(reason_code)
        else:
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
        if len(packet) == 3:
            (cmd, rl, reason_code) = struct.unpack('!BBB', packet)
            return "DISCONNECT, rl="+str(rl)+", reason_code="+str(reason_code)
        else:
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


def get_port(count=1):
    ports_def = os.environ.get('CTEST_RESOURCE_GROUP_0_PORTS')
    if ports_def is not None:
        ports = ports_def.split(";")
        p = ()
        for port in ports:
            (pid, slots) = port.split(",")
            p = p + (int(pid.split(":")[1]),)
        if len(p) == 1:
            return p[0]
        else:
            return p
    else:
        if count == 1:
            if len(sys.argv) == 2:
                return int(sys.argv[1])
            else:
                return 1888
        else:
            if len(sys.argv) >= 1+count:
                p = ()
                for i in range(0, count):
                    p = p + (int(sys.argv[1+i]),)
                return p
            else:
                return tuple(range(1888, 1888+count))


def do_ping(sock, error_string="pingresp"):
     do_send_receive(sock, mqtt_packets.gen_pingreq(), mqtt_packets.gen_pingresp(), error_string)

def client_test(client_cmd, client_args, callback, cb_data):
    port = get_port()

    rc = 1

    sock = listen_sock(port)

    args = [Path(get_build_root(), "test", "lib") / client_cmd, str(port)]
    if client_args is not None:
        args = args + client_args

    client = start_client(filename=str(client_cmd).replace('/', '-'), cmd=args)

    try:
        (conn, address) = sock.accept()
        conn.settimeout(10)

        callback(conn, cb_data)
        rc = 0

        conn.close()
    except TestError as err:
        print(err)
    except Exception as err:
        print(err)
        raise
    finally:
        client_rc = wait_for_subprocess(client)
        if client_rc:
            print("test client not finished")
            rc=1
        sock.close()
        if rc:
            (o, e) = client.communicate()
            print(o)
            print(e)
            print(f"Fail: {client_cmd} rc={rc}, client_rc={client_rc}")
            exit(rc)


def get_non_loopback_ip():
    # https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        # doesn't even have to be reachable
        s.connect(('10.254.254.254', 1))
        IP = s.getsockname()[0]
    except Exception:
        # Explicitly not 127.0.0.1 - we want something that doesn't match a
        # certificate SAN
        IP = '127.0.0.2'
    finally:
        s.close()
    return IP


# =============================================
# Websockets wrapper
# =============================================
class WebsocketConnectionError(ValueError):
    pass

class WebsocketWrapper(object):
    OPCODE_CONTINUATION = 0x0
    OPCODE_TEXT = 0x1
    OPCODE_BINARY = 0x2
    OPCODE_CONNCLOSE = 0x8
    OPCODE_PING = 0x9
    OPCODE_PONG = 0xa

    def __init__(self, socket, host, port, is_ssl, path, extra_headers):

        self.connected = False

        self._ssl = is_ssl
        self._host = host
        self._port = port
        self._socket = socket
        self._path = path

        self._sendbuffer = bytearray()
        self._readbuffer = bytearray()

        self._requested_size = 0
        self._payload_head = 0
        self._readbuffer_head = 0

        self._do_handshake(extra_headers)

    def __del__(self):

        self._sendbuffer = None
        self._readbuffer = None

    def _do_handshake(self, extra_headers):

        sec_websocket_key = uuid.uuid4().bytes
        sec_websocket_key = base64.b64encode(sec_websocket_key)

        websocket_headers = {
            "Host": "{self._host:s}:{self._port:d}".format(self=self),
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Origin": "https://{self._host:s}:{self._port:d}".format(self=self),
            "Sec-WebSocket-Key": sec_websocket_key.decode("utf8"),
            "Sec-Websocket-Version": "13",
            "Sec-Websocket-Protocol": "mqtt",
        }

        # This is checked in ws_set_options so it will either be None, a
        # dictionary, or a callable
        if isinstance(extra_headers, dict):
            websocket_headers.update(extra_headers)
        elif callable(extra_headers):
            websocket_headers = extra_headers(websocket_headers)

        header = "\r\n".join([
            "GET {self._path} HTTP/1.1".format(self=self),
            "\r\n".join("{}: {}".format(i, j)
                        for i, j in websocket_headers.items()),
            "\r\n",
        ]).encode("utf8")

        self._socket.send(header)

        has_secret = False
        has_upgrade = False

        while True:
            # read HTTP response header as lines
            byte = self._socket.recv(1)

            self._readbuffer.extend(byte)

            # line end
            if byte == b"\n":
                if len(self._readbuffer) > 2:
                    # check upgrade
                    if b"connection" in str(self._readbuffer).lower().encode('utf-8'):
                        if b"upgrade" not in str(self._readbuffer).lower().encode('utf-8'):
                            raise WebsocketConnectionError(
                                "WebSocket handshake error, connection not upgraded")
                        else:
                            has_upgrade = True

                    # check key hash
                    if b"sec-websocket-accept" in str(self._readbuffer).lower().encode('utf-8'):
                        GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

                        server_hash = self._readbuffer.decode(
                            'utf-8').split(": ", 1)[1]
                        server_hash = server_hash.strip().encode('utf-8')

                        client_hash = sec_websocket_key.decode('utf-8') + GUID
                        client_hash = hashlib.sha1(client_hash.encode('utf-8'))
                        client_hash = base64.b64encode(client_hash.digest())

                        if server_hash != client_hash:
                            raise WebsocketConnectionError(
                                "WebSocket handshake error, invalid secret key")
                        else:
                            has_secret = True
                else:
                    # ending linebreak
                    break

                # reset linebuffer
                self._readbuffer = bytearray()

            # connection reset
            elif not byte:
                raise WebsocketConnectionError("WebSocket handshake error")

        if not has_upgrade or not has_secret:
            raise WebsocketConnectionError("WebSocket handshake error")

        self._readbuffer = bytearray()
        self.connected = True

    def _create_frame(self, opcode, data, do_masking=1):

        header = bytearray()
        length = len(data)

        mask_key = bytearray(os.urandom(4))
        mask_flag = do_masking

        # 1 << 7 is the final flag, we don't send continuated data
        header.append(1 << 7 | opcode)

        if length < 126:
            header.append(mask_flag << 7 | length)

        elif length < 65536:
            header.append(mask_flag << 7 | 126)
            header += struct.pack("!H", length)

        elif length < 0x8000000000000001:
            header.append(mask_flag << 7 | 127)
            header += struct.pack("!Q", length)

        else:
            raise ValueError("Maximum payload size is 2^63")

        if mask_flag == 1:
            for index in range(length):
                data[index] ^= mask_key[index % 4]
            data = mask_key + data

        return header + data

    def _buffered_read(self, length):

        # try to recv and store needed bytes
        wanted_bytes = length - (len(self._readbuffer) - self._readbuffer_head)
        if wanted_bytes > 0:

            data = self._socket.recv(wanted_bytes)

            if not data:
                raise ConnectionAbortedError
            else:
                self._readbuffer.extend(data)

            if len(data) < wanted_bytes:
                print(f"{len(data)} {wanted_bytes}")
                raise BlockingIOError

        self._readbuffer_head += length
        return self._readbuffer[self._readbuffer_head - length:self._readbuffer_head]

    def _recv_impl(self, length):

        # try to decode websocket payload part from data
        try:

            self._readbuffer_head = 0

            result = None

            chunk_startindex = self._payload_head
            chunk_endindex = self._payload_head + length

            header1 = self._buffered_read(1)
            header2 = self._buffered_read(1)

            opcode = (header1[0] & 0x0f)
            maskbit = (header2[0] & 0x80) == 0x80
            lengthbits = (header2[0] & 0x7f)
            payload_length = lengthbits
            mask_key = None

            # read length
            if lengthbits == 0x7e:

                value = self._buffered_read(2)
                payload_length, = struct.unpack("!H", value)

            elif lengthbits == 0x7f:

                value = self._buffered_read(8)
                payload_length, = struct.unpack("!Q", value)

            # read mask
            if maskbit:
                mask_key = self._buffered_read(4)

            # if frame payload is shorter than the requested data, read only the possible part
            readindex = chunk_endindex
            if payload_length < readindex:
                readindex = payload_length

            if readindex > 0:
                # get payload chunk
                payload = self._buffered_read(readindex)

                # unmask only the needed part
                if maskbit:
                    for index in range(chunk_startindex, readindex):
                        payload[index] ^= mask_key[index % 4]

                result = payload[chunk_startindex:readindex]
                self._payload_head = readindex
            else:
                payload = bytearray()

            # check if full frame arrived and reset readbuffer and payloadhead if needed
            if readindex == payload_length:
                self._readbuffer = bytearray()
                self._payload_head = 0

                # respond to non-binary opcodes, their arrival is not guaranteed beacause of non-blocking sockets
                if opcode == WebsocketWrapper.OPCODE_CONNCLOSE:
                    frame = self._create_frame(
                        WebsocketWrapper.OPCODE_CONNCLOSE, payload, 0)
                    self._socket.send(frame)

                if opcode == WebsocketWrapper.OPCODE_PING:
                    frame = self._create_frame(
                        WebsocketWrapper.OPCODE_PONG, payload, 0)
                    self._socket.send(frame)

            # This isn't *proper* handling of continuation frames, but given
            # that we only support binary frames, it is *probably* good enough.
            if (opcode == WebsocketWrapper.OPCODE_BINARY or opcode == WebsocketWrapper.OPCODE_CONTINUATION) \
                    and payload_length > 0:
                return result
            else:
                #raise BlockingIOError
                return b""

        except ConnectionError:
            self.connected = False
            return b''

    def _send_impl(self, data):

        # if previous frame was sent successfully
        if len(self._sendbuffer) == 0:
            # create websocket frame
            frame = self._create_frame(
                WebsocketWrapper.OPCODE_BINARY, bytearray(data))
            self._sendbuffer.extend(frame)
            self._requested_size = len(data)

        # try to write out as much as possible
        length = self._socket.send(self._sendbuffer)

        self._sendbuffer = self._sendbuffer[length:]

        if len(self._sendbuffer) == 0:
            # buffer sent out completely, return with payload's size
            return self._requested_size
        else:
            # couldn't send whole data, request the same data again with 0 as sent length
            return 0

    def recv(self, length):
        return self._recv_impl(length)

    def read(self, length):
        return self._recv_impl(length)

    def send(self, data):
        return self._send_impl(data)

    def write(self, data):
        return self._send_impl(data)

    def close(self):
        self._socket.close()

    def fileno(self):
        return self._socket.fileno()

    def pending(self):
        # Fix for bug #131: a SSL socket may still have data available
        # for reading without select() being aware of it.
        if self._ssl:
            return self._socket.pending()
        else:
            # normal socket rely only on select()
            return 0

    def setblocking(self, flag):
        self._socket.setblocking(flag)


def check_features(features):
    for feature in features:
        requirement = "ON"
        if feature[0] == "!":
            feature = feature[1:]
            requirement = "OFF"

        env = os.environ.get(feature)
        if env is not None and env != requirement:
            return False
    return True

def require_features(features):
    if not check_features(features):
        exit(77)

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
