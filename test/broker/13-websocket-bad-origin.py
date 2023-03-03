#!/usr/bin/env python3

from mosq_test_helper import *

rc = 1

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")
        f.write("protocol websockets\n")
        f.write("websockets_origin example.org\n")

def do_test(publish_packet, reason_code, error_string):
    global rc

    rc = 1

    connect_packet = mosq_test.gen_connect("13-malformed-publish-v5", proto_ver=5)

    connack_props = mqtt5_props.gen_uint16_prop(mqtt5_props.PROP_TOPIC_ALIAS_MAXIMUM, 10)
    connack_props += mqtt5_props.gen_byte_prop(mqtt5_props.PROP_RETAIN_AVAILABLE, 0)
    connack_props += mqtt5_props.gen_uint16_prop(mqtt5_props.PROP_RECEIVE_MAXIMUM, 20)
    connack_props += mqtt5_props.gen_byte_prop(mqtt5_props.PROP_MAXIMUM_QOS, 1)

    connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5, properties=connack_props, property_helper=False)

    mid = 0
    disconnect_packet = mosq_test.gen_disconnect(proto_ver=5, reason_code=reason_code)

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
    mosq_test.do_send_receive(sock, publish_packet, disconnect_packet, error_string=error_string)
    rc = 0


port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
write_config(conf_file, port)
broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

try:
    websocket_req_bad = b"GET /mqtt HTTP/1.1\r\n" \
        + b"Host: localhost\r\n" \
        + b"Upgrade: websocket\r\n" \
        + b"Connection: Upgrade\r\n" \
        + B"Sec-WebSocket-Key: 1JaITHdgDZVd/4OE2AzTTA==\r\n" \
        + b"Sec-WebSocket-Protocol: mqtt\r\n" \
        + b"Sec-WebSocket-Version: 13\r\n" \
        + b"Origin: localhost\r\n" \
        + b"\r\n"

    sock = mosq_test.do_client_connect(websocket_req_bad, b"", port=port)
    sock.close()
except BrokenPipeError:
    pass

try:
    websocket_req_good = b"GET /mqtt HTTP/1.1\r\n" \
        + b"Host: localhost\r\n" \
        + b"Upgrade: websocket\r\n" \
        + b"Connection: Upgrade\r\n" \
        + B"Sec-WebSocket-Key: 1JaITHdgDZVd/4OE2AzTTA==\r\n" \
        + b"Sec-WebSocket-Protocol: mqtt\r\n" \
        + b"Sec-WebSocket-Version: 13\r\n" \
        + b"Origin: example.org\r\n" \
        + b"\r\n"

    websocket_resp_good = b"HTTP/1.1 101 Switching Protocols\r\n" \
        + b"Upgrade: WebSocket\r\n" \
        + b"Connection: Upgrade\r\n" \
        + b"Sec-WebSocket-Accept: Ako91O0lxiq8gN0+b9YCijMx8lk=\r\n" \
        + b"Sec-WebSocket-Protocol: mqtt\r\n" \
        + b"\r\n"

    sock = mosq_test.do_client_connect(websocket_req_good, websocket_resp_good, port=port)
    sock.close()

    rc = 0
except Exception as err:
    print(err)
finally:
    broker.terminate()
    if mosq_test.wait_for_subprocess(broker):
        print("broker not terminated")
        if rc == 0: rc=1
    (stdo, stde) = broker.communicate()
    os.remove(conf_file)
    if rc:
        print(stde.decode('utf-8'))
        exit(rc)
