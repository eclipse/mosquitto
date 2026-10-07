#!/usr/bin/env python3

from mosq_test_helper import *
from dynsec_helper import *
import json
import shutil

mosq_test.require_features(["WITH_CONTROL", "WITH_PLUGINS", "WITH_PLUGIN_DYNAMIC_SECURITY", "WITH_TLS"])

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")
        f.write(f"plugin {mosq_paths.plugin_dynamic_security}\n")
        f.write(f"plugin_opt_config_file {Path(str(port), 'dynamic-security.json')}\n")


port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
write_config(conf_file, port)

create_role_command = { "commands": [{
    "command": "createRole", "rolename": "role_one",
    "textname": "Name", "textdescription": "Description",
    "acls":[
        {
            "acltype": "publishClientSend",
            "allow": True,
            "topic": "topic/#",
            "priority": 8
        },
        {
            "acltype": "publishClientSend",
            "allow": True,
            "topic": "topic/2/#",
            "priority": 9
        }
    ], "correlationData": "2" }]
}
create_role_response = {'responses': [{'command': 'createRole', 'correlationData': '2'}]}

modify_role_command = { "commands": [{
    "command": "modifyRole", "rolename": "role_one",
    "textname": "Modified name", "textdescription": "Modified description", 'allowwildcardsubs': False,
    "acls":[
        {
            "acltype": "publishClientReceive",
            "allow": True,
            "topic": "topic/#",
            "priority": 2
        },
        {
            "acltype": "publishClientReceive",
            "allow": True,
            "topic": "topic/2/#",
            "priority": 1
        }
    ],
    "correlationData": "3" }]
}
modify_role_response = {'responses': [{'command': 'modifyRole', 'correlationData': '3'}]}


get_role_command1 = { "commands": [{"command": "getRole", "rolename": "role_one"}]}
get_role_response1 = {'responses':[{'command': 'getRole', 'data': {'role': {'rolename': 'role_one',
    'textname': 'Name', 'textdescription': 'Description', 'allowwildcardsubs': True,
    'acls': [
        {
            "acltype": "publishClientSend",
            "topic": "topic/2/#",
            "allow": True,
            "priority": 9
        },
        {
            "acltype": "publishClientSend",
            "topic": "topic/#",
            "allow": True,
            "priority": 8
        }
    ]}}}]}

get_role_command2 = { "commands": [{
    "command": "getRole", "rolename": "role_one"}]}
get_role_response2 = {'responses':[{'command': 'getRole', 'data': {'role': {'rolename': 'role_one',
    'textname': 'Modified name', 'textdescription': 'Modified description', 'allowwildcardsubs': False,
    'acls': [
        {
            "acltype": "publishClientReceive",
            "topic": "topic/#",
            "allow": True,
            "priority": 2
        },
        {
            "acltype": "publishClientReceive",
            "topic": "topic/2/#",
            "allow": True,
            "priority": 1
        }
    ]}}}]}

rc = 1
connect_packet = mqtt_packets.gen_connect("ctrl-test", username="admin", password="admin")
connack_packet = mqtt_packets.gen_connack(rc=0)

mid = 2
subscribe_packet = mqtt_packets.gen_subscribe(mid, "$CONTROL/dynamic-security/#", 1)
suback_packet = mqtt_packets.gen_suback(mid, 1)

try:
    os.mkdir(str(port))
    shutil.copyfile(str(Path(__file__).resolve().parent / "dynamic-security-init.json"), "%d/dynamic-security.json" % (port))
except FileExistsError:
    pass

broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

try:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port)
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

    # Add role
    command_check(sock, create_role_command, create_role_response)

    # Get role
    command_check(sock, get_role_command1, get_role_response1)

    # Modify role
    command_check(sock, modify_role_command, modify_role_response)

    # Get role
    command_check(sock, get_role_command2, get_role_response2)

    # Kill broker and restart, checking whether our changes were saved.
    mosq_test.terminate_broker(broker)
    broker_terminate_rc = 0
    if mosq_test.wait_for_subprocess(broker):
        print("broker not terminated")
        broker_terminate_rc = 1
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port)
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

    # Get role
    command_check(sock, get_role_command2, get_role_response2)

    check_details(sock, 1, 0, 2, 2)

    rc = broker_terminate_rc

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
    mosq_test.terminate_broker(broker)
    if mosq_test.wait_for_subprocess(broker):
        print("broker not terminated")
        if rc == 0: rc=1
    if rc:
        print(mosq_test.broker_log(broker))


exit(rc)
