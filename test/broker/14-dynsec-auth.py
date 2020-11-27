#!/usr/bin/env python3

from mosq_test_helper import *
import json
import shutil

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous false\n")
        f.write("plugin ../../plugins/dynamic-security/mosquitto_dynamic_security.so\n")
        f.write("plugin_opt_config_file %d/dynamic-security.json\n" % (port))

def command_check(sock, command_payload, expected_response):
    command_packet = mosq_test.gen_publish(topic="$CONTROL/dynamic-security/v1", qos=0, payload=json.dumps(command_payload))
    sock.send(command_packet)
    response = json.loads(mosq_test.read_publish(sock))
    if response != expected_response:
        print(expected_response)
        print(response)
        raise ValueError(response)



port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
write_config(conf_file, port)

add_client_command_with_id = { "commands": [{
    "command": "createClient", "username": "user_one",
    "password": "password", "clientid": "cid",
    "correlationData": "2" }]
}
add_client_response_with_id = {'responses': [{'command': 'createClient', 'correlationData': '2'}]}

add_client_command_without_id = { "commands": [{
    "command": "createClient", "username": "user_two",
    "password": "asdfgh",
    "correlationData": "3" }]
}
add_client_response_without_id = {'responses': [{'command': 'createClient', 'correlationData': '3'}]}

set_client_id_command = { "commands": [{
    "command": "setClientId", "username": "user_two", "clientid": "new-cid",
    "correlationData": "5" }]
}
set_client_id_response = {'responses': [{'command': 'setClientId', 'correlationData': '5'}]}

# No password defined, this client should never be able to connect.
add_client_command_without_pw = { "commands": [{
    "command": "createClient", "username": "user_three",
    "correlationData": "4" }]
}
add_client_response_without_pw = {'responses': [{'command': 'createClient', 'correlationData': '4'}]}

rc = 1
keepalive = 10
connect_packet = mosq_test.gen_connect("ctrl-test", keepalive=keepalive, username="admin", password="admin")
connack_packet = mosq_test.gen_connack(rc=0)

mid = 2
subscribe_packet = mosq_test.gen_subscribe(mid, "$CONTROL/dynamic-security/#", 1)
suback_packet = mosq_test.gen_suback(mid, 1)

# Success
connect_packet_with_id1 = mosq_test.gen_connect("cid", keepalive=keepalive, username="user_one", password="password", proto_ver=5)
connack_packet_with_id1 = mosq_test.gen_connack(rc=0, proto_ver=5)

# Fail - bad client id
connect_packet_with_id2 = mosq_test.gen_connect("bad-cid", keepalive=keepalive, username="user_one", password="password", proto_ver=5)
connack_packet_with_id2 = mosq_test.gen_connack(rc=mqtt5_rc.MQTT_RC_NOT_AUTHORIZED, proto_ver=5, property_helper=False)

# Fail - bad password
connect_packet_with_id3 = mosq_test.gen_connect("cid", keepalive=keepalive, username="user_one", password="ttt", proto_ver=5)
connack_packet_with_id3 = mosq_test.gen_connack(rc=mqtt5_rc.MQTT_RC_NOT_AUTHORIZED, proto_ver=5, property_helper=False)

# Fail - no password
connect_packet_with_id4 = mosq_test.gen_connect("cid", keepalive=keepalive, username="user_one", proto_ver=5)
connack_packet_with_id4 = mosq_test.gen_connack(rc=mqtt5_rc.MQTT_RC_NOT_AUTHORIZED, proto_ver=5, property_helper=False)

# Success
connect_packet_without_id1 = mosq_test.gen_connect("no-cid", keepalive=keepalive, username="user_two", password="asdfgh", proto_ver=5)
connack_packet_without_id1 = mosq_test.gen_connack(rc=0, proto_ver=5)

# Fail - bad password
connect_packet_without_id2 = mosq_test.gen_connect("no-cid", keepalive=keepalive, username="user_two", password="pass", proto_ver=5)
connack_packet_without_id2 = mosq_test.gen_connack(rc=mqtt5_rc.MQTT_RC_NOT_AUTHORIZED, proto_ver=5, property_helper=False)

# Fail - no password
connect_packet_without_id3 = mosq_test.gen_connect("no-cid", keepalive=keepalive, username="user_two", proto_ver=5)
connack_packet_without_id3 = mosq_test.gen_connack(rc=mqtt5_rc.MQTT_RC_NOT_AUTHORIZED, proto_ver=5, property_helper=False)

# Success
connect_packet_set_id1 = mosq_test.gen_connect("new-cid", keepalive=keepalive, username="user_two", password="asdfgh", proto_ver=5)
connack_packet_set_id1 = mosq_test.gen_connack(rc=0, proto_ver=5)

# Fail - bad client id
connect_packet_set_id2 = mosq_test.gen_connect("bad-cid", keepalive=keepalive, username="user_two", password="asdfgh", proto_ver=5)
connack_packet_set_id2 = mosq_test.gen_connack(rc=mqtt5_rc.MQTT_RC_NOT_AUTHORIZED, proto_ver=5, property_helper=False)


# Fail - bad password
connect_packet_without_pw1 = mosq_test.gen_connect("cid2", keepalive=keepalive, username="user_three", password="pass", proto_ver=5)
connack_packet_without_pw1 = mosq_test.gen_connack(rc=mqtt5_rc.MQTT_RC_NOT_AUTHORIZED, proto_ver=5, property_helper=False)

# Fail - no password
connect_packet_without_pw2 = mosq_test.gen_connect("cid2", keepalive=keepalive, username="user_three", proto_ver=5)
connack_packet_without_pw2 = mosq_test.gen_connack(rc=mqtt5_rc.MQTT_RC_NOT_AUTHORIZED, proto_ver=5, property_helper=False)

# Fail - no username
connect_packet_without_un = mosq_test.gen_connect("cid3", keepalive=keepalive, proto_ver=5)
connack_packet_without_un = mosq_test.gen_connack(rc=mqtt5_rc.MQTT_RC_NOT_AUTHORIZED, proto_ver=5, property_helper=False)

try:
    os.mkdir(str(port))
    shutil.copyfile("dynamic-security-init.json", "%d/dynamic-security.json" % (port))
except FileExistsError:
    pass

broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

try:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port)
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

    # Add client
    command_check(sock, add_client_command_with_id, add_client_response_with_id)
    command_check(sock, add_client_command_without_id, add_client_response_without_id)
    command_check(sock, add_client_command_without_pw, add_client_response_without_pw)

    # Client with username, password, and client id
    csock = mosq_test.do_client_connect(connect_packet_with_id1, connack_packet_with_id1, timeout=5, port=port, connack_error="with id 1")
    csock.close()

    csock = mosq_test.do_client_connect(connect_packet_with_id2, connack_packet_with_id2, timeout=5, port=port, connack_error="with id 2")
    csock.close()

    csock = mosq_test.do_client_connect(connect_packet_with_id3, connack_packet_with_id3, timeout=5, port=port, connack_error="with id 3")
    csock.close()

    csock = mosq_test.do_client_connect(connect_packet_with_id4, connack_packet_with_id4, timeout=5, port=port, connack_error="with id 4")
    csock.close()

    # Client with just username and password
    csock = mosq_test.do_client_connect(connect_packet_without_id1, connack_packet_without_id1, timeout=5, port=port, connack_error="without id 1")
    csock.close()

    csock = mosq_test.do_client_connect(connect_packet_without_id2, connack_packet_without_id2, timeout=5, port=port, connack_error="without id 2")
    csock.close()

    csock = mosq_test.do_client_connect(connect_packet_without_id3, connack_packet_without_id3, timeout=5, port=port, connack_error="without id 3")
    csock.close()

    # Client with no password set
    csock = mosq_test.do_client_connect(connect_packet_without_pw1, connack_packet_without_pw1, timeout=5, port=port, connack_error="without pw 1")
    csock.close()

    csock = mosq_test.do_client_connect(connect_packet_without_pw2, connack_packet_without_pw2, timeout=5, port=port, connack_error="without pw 2")
    csock.close()

    # Add client id to "user_two"
    command_check(sock, set_client_id_command, set_client_id_response)

    csock = mosq_test.do_client_connect(connect_packet_set_id1, connack_packet_set_id1, timeout=5, port=port, connack_error="set id 1")
    csock.close()

    csock = mosq_test.do_client_connect(connect_packet_set_id2, connack_packet_set_id2, timeout=5, port=port, connack_error="set id 2")
    csock.close()

    # No username, anon disabled
    csock = mosq_test.do_client_connect(connect_packet_without_un, connack_packet_without_un, timeout=5, port=port, connack_error="without username")
    csock.close()

    rc = 0

    sock.close()
except mosq_test.TestError:
    pass
finally:
    os.remove(conf_file)
    try:
        os.remove(f"{port}/dynamic-security.json")
    except FileNotFoundError:
        pass
    os.rmdir(f"{port}")
    broker.terminate()
    broker.wait()
    (stdo, stde) = broker.communicate()
    if rc:
        print(stde.decode('utf-8'))


exit(rc)
