#!/usr/bin/env python3

# Check invalid inputs for plugin commands

from mosq_test_helper import *
import json
import shutil

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous true\n")
        f.write("plugin ../../plugins/dynamic-security/mosquitto_dynamic_security.so\n")
        f.write("plugin_opt_config_file %d/dynamic-security.json\n" % (port))

def command_check(sock, command_payload, expected_response, msg=""):
    command_packet = mosq_test.gen_publish(topic="$CONTROL/dynamic-security/v1", qos=0, payload=json.dumps(command_payload))
    sock.send(command_packet)
    response = json.loads(mosq_test.read_publish(sock))
    if response != expected_response:
        print(expected_response)
        print(response)
        if msg != "":
            print(msg)
        raise ValueError(response)


def command_check_text(sock, command_payload, expected_response, msg=""):
    command_packet = mosq_test.gen_publish(topic="$CONTROL/dynamic-security/v1", qos=0, payload=command_payload)
    sock.send(command_packet)
    response = json.loads(mosq_test.read_publish(sock))
    if response != expected_response:
        print(expected_response)
        print(response)
        if msg != "":
            print(msg)
        raise ValueError(response)


port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
write_config(conf_file, port)

# ==========================================================================
# Bad commands
# ==========================================================================

# Invalid JSON
bad1_command = 'not json'
bad1_response = {'responses': [{'command': 'Unknown command', 'error': 'Invalid/missing commands'}]}

# No commands
bad2_command = {}
bad2_response = {'responses': [{'command': 'Unknown command', 'error': 'Invalid/missing commands'}]}

# Commands not an array
bad3_command = {'commands': 'test'}
bad3_response = {'responses': [{'command': 'Unknown command', 'error': 'Invalid/missing commands'}]}

# Empty commands array
bad4_command = {'commands': []}
bad4_response = {'responses': []}

# Empty command
bad5_command = {'commands': ['bad']}
bad5_response = {'responses': [{'command': 'Unknown command', 'error': 'Command not an object'}]}

# Bad array type
bad6_command = {'commands': [{}]}
bad6_response = {'responses': [{'command': 'Unknown command', 'error': 'Missing command'}]}

# Bad command type
bad7_command = {'commands': [{'command':6}]}
bad7_response = {'responses': [{'command': 'Unknown command', 'error': 'Missing command'}]}

# Bad correlationData type
bad8_command = {'commands': [{'command':'command', 'correlationData':6}]}
bad8_response = {'responses': [{'command': 'command', 'error': 'Invalid correlationData data type.'}]}

# Unknown command
bad9_command = {'commands': [{'command':'command'}]}
bad9_response = {'responses': [{'command': 'command', 'error': 'Unknown command'}]}

# ==========================================================================
# setDefaultACLAccess
# ==========================================================================

# Missing actions array
set_default1_command = {'commands': [{'command':'setDefaultACLAccess'}]}
set_default1_response = {'responses': [{'command': 'setDefaultACLAccess', 'error': 'Missing/invalid actions array'}]}

# Actions array not an array
set_default2_command = {'commands': [{'command':'setDefaultACLAccess', 'actions':'bad'}]}
set_default2_response = {'responses': [{'command': 'setDefaultACLAccess', 'error': 'Missing/invalid actions array'}]}


rc = 1
keepalive = 10
connect_packet = mosq_test.gen_connect("ctrl-test", keepalive=keepalive, username="admin", password="admin")
connack_packet = mosq_test.gen_connack(rc=0)

mid = 2
subscribe_packet = mosq_test.gen_subscribe(mid, "$CONTROL/dynamic-security/#", 1)
suback_packet = mosq_test.gen_suback(mid, 1)

try:
    os.mkdir(str(port))
    shutil.copyfile("dynamic-security-init.json", "%d/dynamic-security.json" % (port))
except FileExistsError:
    pass

broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

try:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port)
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

    command_check(sock, bad1_command, bad1_response, "1")
    command_check(sock, bad2_command, bad2_response, "2")
    command_check(sock, bad3_command, bad3_response, "3")
    command_check(sock, bad4_command, bad4_response, "4")
    command_check(sock, bad5_command, bad5_response, "5")
    command_check(sock, bad6_command, bad6_response, "6")
    command_check(sock, bad7_command, bad7_response, "7")
    command_check(sock, bad8_command, bad8_response, "8")
    command_check(sock, bad9_command, bad9_response, "9")

    command_check(sock, set_default1_command, set_default1_response, "1")
    command_check(sock, set_default2_command, set_default2_response, "2")

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
