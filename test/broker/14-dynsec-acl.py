#!/usr/bin/env python3

# Test ACL for allow/deny. This does not consider ACL priority and the ACLs do not overlap.

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


add_client_group_role_command = {"commands":[
    { "command": "createGroup", "groupname": "mygroup" },
    { "command": "createRole", "rolename": "myrole" },
    { "command": "addGroupRole", "groupname": "mygroup", "rolename": "myrole" },
    { "command": "addRoleACL", "rolename": "myrole", "acltype": "subscribeLiteral", "topic": "simple/topic", "allow": True },
    { "command": "addRoleACL", "rolename": "myrole", "acltype": "subscribePattern", "topic": "single-wildcard/+/topic", "allow": True },
    { "command": "addRoleACL", "rolename": "myrole", "acltype": "subscribePattern", "topic": "multilevel-wildcard/#", "allow": True },
    { "command": "addRoleACL", "rolename": "myrole", "acltype": "unsubscribeLiteral", "topic": "simple/topic", "allow": False },
    { "command": "addGroupClient", "groupname": "mygroup", "username": "user_one" }
    ]}

add_client_group_role_response = {'responses': [
    {'command': 'createGroup'},
    {'command': 'createRole'},
    {'command': 'addGroupRole'},
    {'command': 'addRoleACL'}, {'command': 'addRoleACL'},
    {'command': 'addRoleACL'}, {'command': 'addRoleACL'},
    {'command': 'addGroupClient'}
    ]}

add_publish_acl_command = {"commands":[
    { "command": "addRoleACL", "rolename": "myrole", "acltype": "publishClientSend", "topic": "simple/topic", "allow": True },
    { "command": "addRoleACL", "rolename": "myrole", "acltype": "publishClientSend", "topic": "single-wildcard/deny/deny", "priority":10, "allow": False },
    { "command": "addRoleACL", "rolename": "myrole", "acltype": "publishClientSend", "topic": "single-wildcard/+/+", "allow": True },
    { "command": "addRoleACL", "rolename": "myrole", "acltype": "publishClientSend", "topic": "multilevel-wildcard/topic/#", "allow": True },
    { "command": "addRoleACL", "rolename": "myrole", "acltype": "publishClientReceive", "topic": "single-wildcard/bob/bob", "allow": False },
    { "command": "addRoleACL", "rolename": "myrole", "acltype": "publishClientReceive", "topic": "multilevel-wildcard/topic/topic/denied", "allow": False },
    ]}

add_publish_acl_response = {'responses': [
    {'command': 'addRoleACL'}, {'command': 'addRoleACL'},
    {'command': 'addRoleACL'}, {'command': 'addRoleACL'},
    {'command': 'addRoleACL'}, {'command': 'addRoleACL'}
    ]}

delete_role_command = {"commands":[
    { "command": "deleteRole", "rolename": "myrole"}
    ]}
delete_role_response = {'responses': [{'command': 'deleteRole'}]}

rc = 1
keepalive = 10
connect_packet_admin = mosq_test.gen_connect("ctrl-test", keepalive=keepalive, username="admin", password="admin")
connack_packet_admin = mosq_test.gen_connack(rc=0)

mid = 2
subscribe_packet_admin = mosq_test.gen_subscribe(mid, "$CONTROL/dynamic-security/#", 1)
suback_packet_admin = mosq_test.gen_suback(mid, 1)

# Success
connect_packet_with_id1 = mosq_test.gen_connect("cid", keepalive=keepalive, username="user_one", password="password", proto_ver=5)
connack_packet_with_id1 = mosq_test.gen_connack(rc=0, proto_ver=5)

mid = 4
subscribe_simple_packet = mosq_test.gen_subscribe(mid, "simple/topic", 0, proto_ver=5)
suback_simple_packet_success = mosq_test.gen_suback(mid, 0, proto_ver=5)
suback_simple_packet_fail = mosq_test.gen_suback(mid, mqtt5_rc.MQTT_RC_NOT_AUTHORIZED, proto_ver=5)

mid = 5
subscribe_single_packet = mosq_test.gen_subscribe(mid, "single-wildcard/bob/topic", 0, proto_ver=5)
suback_single_packet_success = mosq_test.gen_suback(mid, 0, proto_ver=5)
suback_single_packet_fail = mosq_test.gen_suback(mid, mqtt5_rc.MQTT_RC_NOT_AUTHORIZED, proto_ver=5)

mid = 6
subscribe_multi_packet = mosq_test.gen_subscribe(mid, "multilevel-wildcard/topic/topic/#", 0, proto_ver=5)
suback_multi_packet_success = mosq_test.gen_suback(mid, 0, proto_ver=5)
suback_multi_packet_fail = mosq_test.gen_suback(mid, mqtt5_rc.MQTT_RC_NOT_AUTHORIZED, proto_ver=5)

mid = 7
publish_simple_packet = mosq_test.gen_publish(mid=mid, topic="simple/topic", qos=1, payload="message", proto_ver=5)
puback_simple_packet_success = mosq_test.gen_puback(mid, proto_ver=5)
puback_simple_packet_fail = mosq_test.gen_puback(mid, reason_code=mqtt5_rc.MQTT_RC_NOT_AUTHORIZED, proto_ver=5)

publish_simple_packet_r = mosq_test.gen_publish(topic="simple/topic", qos=0, payload="message", proto_ver=5)

# This message is in single-wildcard/+/+ so could be allowed, but the single-wildcard/deny/deny with higher priority should override
mid = 9
publish_single_packet_denied = mosq_test.gen_publish(mid=mid, topic="single-wildcard/deny/deny", qos=1, payload="message", proto_ver=5)
puback_single_packet_denied_fail = mosq_test.gen_puback(mid, reason_code=mqtt5_rc.MQTT_RC_NOT_AUTHORIZED, proto_ver=5)

mid = 8
publish_single_packet = mosq_test.gen_publish(mid=mid, topic="single-wildcard/bob/topic", qos=1, payload="message", proto_ver=5)
puback_single_packet_success = mosq_test.gen_puback(mid, proto_ver=5)
puback_single_packet_fail = mosq_test.gen_puback(mid, reason_code=mqtt5_rc.MQTT_RC_NOT_AUTHORIZED, proto_ver=5)

publish_single_packet_r = mosq_test.gen_publish(topic="single-wildcard/bob/topic", qos=0, payload="message", proto_ver=5)

mid = 9
publish_multi_packet = mosq_test.gen_publish(mid=mid, topic="multilevel-wildcard/topic/topic/allowed", qos=1, payload="message", proto_ver=5)
puback_multi_packet_success = mosq_test.gen_puback(mid, proto_ver=5)
puback_multi_packet_fail = mosq_test.gen_puback(mid, reason_code=mqtt5_rc.MQTT_RC_NOT_AUTHORIZED, proto_ver=5)

mid = 10
publish_multi_denied_packet = mosq_test.gen_publish(mid=mid, topic="multilevel-wildcard/topic/topic/denied", qos=1, payload="message", proto_ver=5)
puback_multi_denied_packet = mosq_test.gen_puback(mid, proto_ver=5)

publish_multi_packet_r = mosq_test.gen_publish(topic="multilevel-wildcard/topic/topic/allowed", qos=0, payload="message", proto_ver=5)

mid = 11
unsubscribe_simple_packet = mosq_test.gen_unsubscribe(mid, "simple/topic", proto_ver=5)
unsuback_simple_packet_fail = mosq_test.gen_unsuback(mid, mqtt5_rc.MQTT_RC_NOT_AUTHORIZED, proto_ver=5)

mid = 12
unsubscribe_single_packet = mosq_test.gen_unsubscribe(mid, "single-wildcard/bob/topic", proto_ver=5)
unsuback_single_packet_success = mosq_test.gen_unsuback(mid, 0, proto_ver=5)

mid = 13
unsubscribe_multi_packet = mosq_test.gen_unsubscribe(mid, "multilevel-wildcard/topic/topic/#", proto_ver=5)
unsuback_multi_packet_success = mosq_test.gen_unsuback(mid, 0, proto_ver=5)

disconnect_kick_packet = mosq_test.gen_disconnect(reason_code=mqtt5_rc.MQTT_RC_ADMINISTRATIVE_ACTION, proto_ver=5)

try:
    os.mkdir(str(port))
    shutil.copyfile("dynamic-security-init.json", "%d/dynamic-security.json" % (port))
except FileExistsError:
    pass

broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

try:
    sock = mosq_test.do_client_connect(connect_packet_admin, connack_packet_admin, timeout=5, port=port)
    mosq_test.do_send_receive(sock, subscribe_packet_admin, suback_packet_admin, "suback")

    # Add client
    command_check(sock, add_client_command_with_id, add_client_response_with_id)

    # Client with username, password, and client id
    csock = mosq_test.do_client_connect(connect_packet_with_id1, connack_packet_with_id1, timeout=5, port=port, connack_error="connack 1")

    # Subscribe to "simple/topic" - not allowed
    mosq_test.do_send_receive(csock, subscribe_simple_packet, suback_simple_packet_fail, "suback simple 1")

    # Subscribe to "single-wildcard/bob/topic" - not allowed
    mosq_test.do_send_receive(csock, subscribe_single_packet, suback_single_packet_fail, "suback single 1")

    # Subscribe to "multilevel-wildcard/topic/topic/topic" - not allowed
    mosq_test.do_send_receive(csock, subscribe_multi_packet, suback_multi_packet_fail, "suback multi 1")

    # Publish to "simple/topic" - not allowed
    mosq_test.do_send_receive(csock, publish_simple_packet, puback_simple_packet_fail, "puback simple 1")

    # Publish to "single-wildcard/bob/topic" - not allowed
    mosq_test.do_send_receive(csock, publish_single_packet, puback_single_packet_fail, "puback single 1")

    # Publish to "multilevel-wildcard/topic/topic/topic" - not allowed
    mosq_test.do_send_receive(csock, publish_multi_packet, puback_multi_packet_fail, "puback multi 1")

    # Create a group, add a role to the group, add the client to the group
    # Add some subscribe/unsubscribe ACLs - this will kick the client
    command_check(sock, add_client_group_role_command, add_client_group_role_response)

    mosq_test.expect_packet(csock, "disconnect kick 1", disconnect_kick_packet)
    csock.close()

    # Reconnect
    csock = mosq_test.do_client_connect(connect_packet_with_id1, connack_packet_with_id1, timeout=5, port=port, connack_error="connack 2")

    # Subscribe to "simple/topic" - this is now allowed
    mosq_test.do_send_receive(csock, subscribe_simple_packet, suback_simple_packet_success, "suback simple 2")

    # Subscribe to "single-wildcard/bob/topic" - this is now allowed
    mosq_test.do_send_receive(csock, subscribe_single_packet, suback_single_packet_success, "suback single 2")

    # Subscribe to "multilevel-wildcard/topic/topic/topic" - this is now allowed
    mosq_test.do_send_receive(csock, subscribe_multi_packet, suback_multi_packet_success, "suback multi 2")

    # Publish to "simple/topic" - not allowed
    mosq_test.do_send_receive(csock, publish_simple_packet, puback_simple_packet_fail, "puback 2")

    # Publish to "single-wildcard/bob/topic" - not allowed
    mosq_test.do_send_receive(csock, publish_single_packet, puback_single_packet_fail, "puback single 2")

    # Publish to "multilevel-wildcard/topic/topic/topic" - not allowed
    mosq_test.do_send_receive(csock, publish_multi_packet, puback_multi_packet_fail, "puback multi 2")

    # Add some publish ACLs - this will kick the client
    command_check(sock, add_publish_acl_command, add_publish_acl_response)

    mosq_test.expect_packet(csock, "disconnect kick 2", disconnect_kick_packet)
    csock.close()

    # Reconnect
    csock = mosq_test.do_client_connect(connect_packet_with_id1, connack_packet_with_id1, timeout=5, port=port, connack_error="connack 3")

    # Subscribe to "simple/topic" - this is now allowed
    mosq_test.do_send_receive(csock, subscribe_simple_packet, suback_simple_packet_success, "suback simple 3")

    # Subscribe to "single-wildcard/bob/topic" - this is now allowed
    mosq_test.do_send_receive(csock, subscribe_single_packet, suback_single_packet_success, "suback single 3")

    # Subscribe to "multilevel-wildcard/topic/topic/allowed" - this is now allowed
    mosq_test.do_send_receive(csock, subscribe_multi_packet, suback_multi_packet_success, "suback multi 3")

    # Publish to "simple/topic" - this is now allowed
    csock.send(publish_simple_packet)
    mosq_test.receive_unordered(csock, publish_simple_packet_r, puback_simple_packet_success, "puback simple 3 / publish r")

    # Publish to "single-wildcard/bob/topic" - this is now allowed
    csock.send(publish_single_packet)
    mosq_test.receive_unordered(csock, publish_single_packet_r, puback_single_packet_success, "puback single 3 / publish r")

    # Publish to "single-wildcard/deny/deny" - this is stillnot allowed
    mosq_test.do_send_receive(csock, publish_single_packet_denied, puback_single_packet_denied_fail, "puback single denied 1")

    # Publish to "multilevel-wildcard/topic/topic/allowed" - this is now allowed
    csock.send(publish_multi_packet)
    mosq_test.receive_unordered(csock, publish_multi_packet_r, puback_multi_packet_success, "puback multi 3 / publish r")

    # Publish to "multilevel-wildcard/topic/topic/denied" - receiving is denied by publishClientReceive
    mosq_test.do_send_receive(csock, publish_multi_denied_packet, puback_multi_denied_packet, "puback multi denied")
    mosq_test.do_ping(csock)

    # Simple unsubscribe should be denied
    mosq_test.do_send_receive(csock, unsubscribe_simple_packet, unsuback_simple_packet_fail, "unsuback simple 1")

    # Single unsubscribe should be allowed
    mosq_test.do_send_receive(csock, unsubscribe_single_packet, unsuback_single_packet_success, "unsuback single 1")

    # Multi unsubscribe should be allowed
    mosq_test.do_send_receive(csock, unsubscribe_multi_packet, unsuback_multi_packet_success, "unsuback multi 1")

    # Delete the role, client should be kicked
    command_check(sock, delete_role_command, delete_role_response)

    mosq_test.expect_packet(csock, "disconnect kick 3", disconnect_kick_packet)
    csock.close()

    # Reconnect - these should all be denied again.
    csock = mosq_test.do_client_connect(connect_packet_with_id1, connack_packet_with_id1, timeout=5, port=port, connack_error="connack 4")

    # Subscribe to "simple/topic" - not allowed
    mosq_test.do_send_receive(csock, subscribe_simple_packet, suback_simple_packet_fail, "suback simple 4")

    # Subscribe to "single-wildcard/bob/topic" - not allowed
    mosq_test.do_send_receive(csock, subscribe_single_packet, suback_single_packet_fail, "suback single 4")

    # Subscribe to "multilevel-wildcard/topic/topic/topic" - not allowed
    mosq_test.do_send_receive(csock, subscribe_multi_packet, suback_multi_packet_fail, "suback multi 4")

    # Publish to "simple/topic" - not allowed
    mosq_test.do_send_receive(csock, publish_simple_packet, puback_simple_packet_fail, "puback simple 4")

    # Publish to "single-wildcard/bob/topic" - not allowed
    mosq_test.do_send_receive(csock, publish_single_packet, puback_single_packet_fail, "puback single 4")

    # Publish to "multilevel-wildcard/topic/topic/topic" - not allowed
    mosq_test.do_send_receive(csock, publish_multi_packet, puback_multi_packet_fail, "puback multi 4")

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

publishClientSend
publishClientReceive
subscribeLiteral
subscribePattern
