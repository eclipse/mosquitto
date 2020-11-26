#!/usr/bin/env python3

# Test the anonymous group support by adding a group, setting the anon group, adding a role to the group and checking a subscription.
from mosq_test_helper import *
import json
import shutil

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")
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

get_anon_group_none_command = { "commands": [{
    "command": "getAnonymousGroup",
    "correlationData": "2" }]
}
get_anon_group_none_response = {'responses': [{'command': 'getAnonymousGroup',
    'data': {'group': {'groupname': ''}},
    'correlationData': '2'}]}

create_group_set_anon_command = { "commands": [
    { "command": "createGroup", "groupname": "anon-clients", "correlationData": "3" },
    { "command": "setAnonymousGroup", "groupname": "anon-clients", "correlationData": "4" }
    ]
}
create_group_set_anon_response = {'responses': [
    {'command': 'createGroup', 'correlationData': '3'},
    {'command': 'setAnonymousGroup', 'correlationData': '4'},
    ]}


get_anon_group_command = { "commands": [{
    "command": "getAnonymousGroup",
    "correlationData": "3" }]
}
get_anon_group_response = {'responses': [{'command': 'getAnonymousGroup',
    'data': {'group': {'groupname': 'anon-clients'}},
    'correlationData': '3'}]}


create_role_apply_command = { "commands": [
    { "command": "createRole", "rolename": "anon", "correlationData": "4" },
    { "command": "addRoleACL", "rolename": "anon",
		"acltype": "subscribeLiteral", "topic": "anon/topic", "allow": True,
        "correlationData": "5" },
    { "command": "addGroupRole", "groupname": "anon-clients",
        "rolename": "anon", "correlationData": "6"}
    ]
}
create_role_apply_response = {'responses': [
    {'command': 'createRole', 'correlationData': '4'},
    {'command': 'addRoleACL', 'correlationData': '5'},
    {'command': 'addGroupRole', 'correlationData': '6'}
    ]}



rc = 1
keepalive = 10

# Admin
connect_packet_admin = mosq_test.gen_connect("ctrl-test", keepalive=keepalive, username="admin", password="admin")
connack_packet_admin = mosq_test.gen_connack(rc=0)

mid = 1
subscribe_packet_admin = mosq_test.gen_subscribe(mid, "$CONTROL/dynamic-security/#", 1)
suback_packet_admin = mosq_test.gen_suback(mid, 1)

# Client
connect_packet = mosq_test.gen_connect("cid", keepalive=keepalive, proto_ver=5)
connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

mid = 1
subscribe_packet = mosq_test.gen_subscribe(mid, "anon/topic", qos=1, proto_ver=5)
suback_packet_fail = mosq_test.gen_suback(mid, mqtt5_rc.MQTT_RC_NOT_AUTHORIZED, proto_ver=5)
suback_packet_success = mosq_test.gen_suback(mid, 1, proto_ver=5)

disconnect_packet_kick = mosq_test.gen_disconnect(reason_code=mqtt5_rc.MQTT_RC_ADMINISTRATIVE_ACTION, proto_ver=5)

try:
    os.mkdir(str(port))
    shutil.copyfile("dynamic-security-init.json", "%d/dynamic-security.json" % (port))
except FileExistsError:
    pass

broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

try:
    sock = mosq_test.do_client_connect(connect_packet_admin, connack_packet_admin, timeout=5, port=port)
    mosq_test.do_send_receive(sock, subscribe_packet_admin, suback_packet_admin, "suback admin")

    # Add client
    command_check(sock, get_anon_group_none_command, get_anon_group_none_response)

    # Client is anon, there is no anon group, so subscribe should fail
    csock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port)
    mosq_test.do_send_receive(csock, subscribe_packet, suback_packet_fail, "suback 1")

    # Add group, and set to anon
    command_check(sock, create_group_set_anon_command, create_group_set_anon_response)
    command_check(sock, get_anon_group_command, get_anon_group_response)

    # Anon group is changed, so we are kicked
    mosq_test.expect_packet(csock, "disconnect 1", disconnect_packet_kick)
    csock.close()

    # Reconnect, subscribe should still fail
    csock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port)
    mosq_test.do_send_receive(csock, subscribe_packet, suback_packet_fail, "suback 2")

    # Add role with subscribe ACL, and apply to anon group
    command_check(sock, create_role_apply_command, create_role_apply_response)

    # Anon group is changed, so we are kicked
    mosq_test.expect_packet(csock, "disconnect 2", disconnect_packet_kick)
    csock.close()

    # Reconnect, subscribe should now succeed
    csock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port)
    mosq_test.do_send_receive(csock, subscribe_packet, suback_packet_success, "suback 3")

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
