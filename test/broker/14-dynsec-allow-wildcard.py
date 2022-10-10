#!/usr/bin/env python3

# Test for allowwildcardsubs behaviour

from mosq_test_helper import *
import json
import shutil

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous false\n")
        f.write(f"plugin {mosq_test.get_build_root()}/plugins/dynamic-security/mosquitto_dynamic_security.so\n")
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


add_client_group_role_command = {"commands":[
    { "command": "createGroup", "groupname": "mygroup" },
    { "command": "createRole", "rolename": "myrole", "allowwildcardsubs": True},
    { "command": "addGroupRole", "groupname": "mygroup", "rolename": "myrole" },
    { "command": "addRoleACL", "rolename": "myrole", "acltype": "subscribePattern", "topic": "multilevel-wildcard/#", "allow": True },
    { "command": "addGroupClient", "groupname": "mygroup", "username": "user_one" }
    ]}

add_client_group_role_response = {'responses': [
    {'command': 'createGroup'},
    {'command': 'createRole'},
    {'command': 'addGroupRole'},
    {'command': 'addRoleACL'},
    {'command': 'addGroupClient'}
    ]}

modify_role_command = {"commands":[
    { "command": "modifyRole", "rolename": "myrole", "allowwildcardsubs": False}
    ]}

modify_role_response = {"responses":[
    { "command": "modifyRole"}
    ]}

rc = 1
connect_packet_admin = mosq_test.gen_connect("ctrl-test", username="admin", password="admin")
connack_packet_admin = mosq_test.gen_connack(rc=0)

mid = 2
subscribe_packet_admin = mosq_test.gen_subscribe(mid, "$CONTROL/dynamic-security/#", 1)
suback_packet_admin = mosq_test.gen_suback(mid, 1)

# Success
connect_packet = mosq_test.gen_connect("cid", username="user_one", password="password", proto_ver=5)
connack_packet = mosq_test.gen_connack(rc=0, proto_ver=5)

mid = 4
subscribe_packet = mosq_test.gen_subscribe(mid, "multilevel-wildcard/#", 0, proto_ver=5)
suback_packet_success = mosq_test.gen_suback(mid, 0, proto_ver=5)
suback_packet_fail = mosq_test.gen_suback(mid, mqtt5_rc.MQTT_RC_NOT_AUTHORIZED, proto_ver=5)

disconnect_kick_packet = mosq_test.gen_disconnect(reason_code=mqtt5_rc.MQTT_RC_ADMINISTRATIVE_ACTION, proto_ver=5)

try:
    os.mkdir(str(port))
    shutil.copyfile(str(Path(__file__).resolve().parent / "dynamic-security-init.json"), "%d/dynamic-security.json" % (port))
except FileExistsError:
    pass

broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

try:
    sock = mosq_test.do_client_connect(connect_packet_admin, connack_packet_admin, timeout=5, port=port)
    mosq_test.do_send_receive(sock, subscribe_packet_admin, suback_packet_admin, "suback")

    # Add client
    command_check(sock, add_client_command_with_id, add_client_response_with_id)

    # Create a group, add a role to the group, add the client to the group
    command_check(sock, add_client_group_role_command, add_client_group_role_response)

    # Client with username, password, and client id
    csock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port, connack_error="connack 1")

    # Subscribe to "multilevel-wildcard/#" - allowed
    mosq_test.do_send_receive(csock, subscribe_packet, suback_packet_success, "suback # allowed")

    # Modify role - this will kick the client and remove the ability to subscribe to wildcards
    command_check(sock, modify_role_command, modify_role_response)

    mosq_test.expect_packet(csock, "disconnect kick 1", disconnect_kick_packet)
    csock.close()

    # Reconnect
    csock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port, connack_error="connack 2")

    # Subscribe to "multilevel-wildcard/#" - not allowed
    mosq_test.do_send_receive(csock, subscribe_packet, suback_packet_fail, "suback # not allowed")

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
    shutil.rmtree(f"{port}")
    broker.terminate()
    if mosq_test.wait_for_subprocess(broker):
        print("broker not terminated")
        if rc == 0: rc=1
    (stdo, stde) = broker.communicate()
    if rc:
        print(stde.decode('utf-8'))


exit(rc)
