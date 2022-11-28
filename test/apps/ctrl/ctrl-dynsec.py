#!/usr/bin/env python3

from mosq_test_helper import *
import json
import shutil

def write_config(filename, ports):
    with open(filename, 'w') as f:
        f.write(f"global_plugin {mosq_test.get_build_root()}/plugins/dynamic-security/mosquitto_dynamic_security.so\n")
        f.write(f"plugin_opt_config_file {ports[0]}/dynamic-security.json\n")
        f.write("allow_anonymous false\n")
        f.write(f"listener {ports[0]}\n")
        f.write(f"listener {ports[1]}\n")
        f.write(f"certfile {mosq_test.get_build_root()}/test/ssl/server.crt\n")
        f.write(f"keyfile {mosq_test.get_build_root()}/test/ssl/server.key\n")

def ctrl_dynsec_cmd(args, ports, response=None, input=None):
    opts = ["-u", "admin",
            "-P", "newadmin",]

    if response is None:
        opts += [
                "-p", str(ports[0]),
                "-q", "1"
                 ]
    else:
        opts += ["-p", str(ports[1])]
        opts += ["--cafile", f"{mosq_test.get_build_root()}/test/ssl/all-ca.crt"]

    proc = subprocess.run([mosq_test.get_build_root()+"/apps/mosquitto_ctrl/mosquitto_ctrl"]
                    + opts + ["dynsec"] + args,
                    env=env, capture_output=True, encoding='utf-8', timeout=2, input=input)

    if response is not None:
        if proc.stdout != response:
            print(len(proc.stdout))
            print(len(response))
            raise ValueError(proc.stdout)

    if proc.returncode != 0:
        raise ValueError(args)

def ctrl_dynsec_file_cmd(args, ports, response=None):
    opts = ["-f", f"{ports[0]}/dynamic-security.json"]

    proc = subprocess.run([mosq_test.get_build_root()+"/apps/mosquitto_ctrl/mosquitto_ctrl"]
                    + opts + ["dynsec"] + args,
                    env=env, capture_output=True, encoding='utf-8')

    if response is not None:
        if proc.stdout != response:
            raise ValueError(proc.stdout)

    if proc.returncode != 0:
        raise ValueError(args)



ports = mosq_test.get_port(2)
conf_file = os.path.basename(__file__).replace('.py', '.conf')
write_config(conf_file, ports)

env = dict(os.environ)
env['LD_LIBRARY_PATH'] = mosq_test.get_build_root() + '/lib'

if not os.path.exists(str(ports[0])):
    os.mkdir(str(ports[0]))

# Generate initial dynsec file
ctrl_dynsec_cmd(["init", f"{ports[0]}/dynamic-security.json", "admin", "admin"], ports)

ctrl_dynsec_file_cmd(["help"], ports) # get the help, don't check the response though
ctrl_dynsec_file_cmd(["setClientPassword", "admin", "newadmin", "-i", "10000"], ports)

# Then start broker
broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=ports[0], nolog=True)

try:
    rc = 1

    # Set default access to opposite of normal
    ctrl_dynsec_cmd(["setDefaultACLAccess", "publishClientSend", "allow"], ports)
    ctrl_dynsec_cmd(["setDefaultACLAccess", "publishClientReceive", "deny"], ports)
    ctrl_dynsec_cmd(["setDefaultACLAccess", "subscribe", "allow"], ports)
    ctrl_dynsec_cmd(["setDefaultACLAccess", "unsubscribe", "deny"], ports)

    # Verify
    ctrl_dynsec_cmd(["getDefaultACLAccess"], ports, response="publishClientSend    : allow\npublishClientReceive : deny\nsubscribe            : allow\nunsubscribe          : deny\n")

    # Create clients
    ctrl_dynsec_cmd(["createClient", "username1", "-p", "password1"], ports) # password, no client id
    ctrl_dynsec_cmd(["createClient", "username2", "-p", "password2", "-c", "clientid2"], ports) # password and client id
    ctrl_dynsec_cmd(["createClient", "username3"], ports, input="pw\npw\n") # password, no client id
    ctrl_dynsec_cmd(["createClient", "username4"], ports, input="\n\n") # password, no client id
    ctrl_dynsec_cmd(["createClient", "username5"], ports, input="not\nmatching\n")

    # List clients
    ctrl_dynsec_cmd(["listClients"], ports, response="admin\nusername1\nusername2\nusername3\nusername4\n")
    ctrl_dynsec_cmd(["listClients", "1"], ports, response="admin\n") # with count
    ctrl_dynsec_cmd(["listClients", "1", "1"], ports, response="username1\n") # with count, offset

    # Create groups
    ctrl_dynsec_cmd(["createGroup", "group1"], ports)
    ctrl_dynsec_cmd(["createGroup", "group2"], ports)
    ctrl_dynsec_cmd(["createGroup", "group3"], ports)

    #List groups
    ctrl_dynsec_cmd(["listGroups"], ports, response="group1\ngroup2\ngroup3\n")
    ctrl_dynsec_cmd(["listGroups", "1"], ports, response="group1\n")
    ctrl_dynsec_cmd(["listGroups", "1", "1"], ports, response="group2\n")

    # Add client to group
    ctrl_dynsec_cmd(["addGroupClient", "group1", "username1", "10"], ports)

    # Get anonymous group
    ctrl_dynsec_cmd(["getAnonymousGroup"], ports, response="\n")

    # Set anon as anonymous group
    ctrl_dynsec_cmd(["setAnonymousGroup", "group2"], ports)

    # Verify
    ctrl_dynsec_cmd(["getAnonymousGroup"], ports, response="group2\n")

    # Create roles
    ctrl_dynsec_cmd(["createRole", "role1"], ports)
    ctrl_dynsec_cmd(["createRole", "role2"], ports)
    ctrl_dynsec_cmd(["createRole", "role3"], ports)
    #Delete a role:               deleteRole        <rolename>

    ctrl_dynsec_cmd(["deleteRole", "role3"], ports) # repeat with count, offset

    # Add a role to a client
    ctrl_dynsec_cmd(["addClientRole", "username1", "role1", "20"], ports)

    # Add a role to a group
    ctrl_dynsec_cmd(["addGroupRole", "group1", "role2", "15"], ports)

    ctrl_dynsec_cmd(["getGroup", "group1"], ports) # repeat with count, offset

    # Add ACLs
    ctrl_dynsec_cmd(["addRoleACL", "role1", "publishClientSend", "#", "allow", "1"], ports)
    ctrl_dynsec_cmd(["addRoleACL", "role1", "publishClientReceive", "#", "allow", "2"], ports)
    ctrl_dynsec_cmd(["addRoleACL", "role1", "subscribeLiteral", "#", "allow", "1"], ports)
    ctrl_dynsec_cmd(["addRoleACL", "role1", "subscribePattern", "#", "allow", "2"], ports)
    ctrl_dynsec_cmd(["addRoleACL", "role1", "unsubscribeLiteral", "#", "deny", "1"], ports)
    ctrl_dynsec_cmd(["addRoleACL", "role1", "unsubscribePattern", "#", "deny", "2"], ports)
    ctrl_dynsec_cmd(["addRoleACL", "role2", "publishClientSend", "#", "allow", "3"], ports)
    ctrl_dynsec_cmd(["addRoleACL", "role2", "publishClientReceive", "#", "allow"], ports)

    # List roles
    ctrl_dynsec_cmd(["listRoles"], ports, response="admin\nrole1\nrole2\n")
    ctrl_dynsec_cmd(["listRoles", "1"], ports, response="admin\n")
    ctrl_dynsec_cmd(["listRoles", "1", "1"], ports, response="role1\n")

    # Get role
    ctrl_dynsec_cmd(["getRole", "role1"], ports, response="Rolename: role1\nACLs:     publishClientSend    : allow : # (priority: 1)\n          publishClientReceive : allow : # (priority: 2)\n          subscribeLiteral     : allow : # (priority: 1)\n          subscribePattern     : allow : # (priority: 2)\n          unsubscribeLiteral   : deny  : # (priority: 1)\n          unsubscribePattern   : deny  : # (priority: 2)\n")

    # Get client
    ctrl_dynsec_cmd(["getClient", "username1"], ports, response="Username:    username1\nClientid:\nRoles:       role1 (priority: 20)\nGroups:      group1 (priority: 10)\n")

    # Disable client
    ctrl_dynsec_cmd(["disableClient", "username1"], ports)

    # Verify client
    ctrl_dynsec_cmd(["getClient", "username1"], ports, response="Username:    username1\nClientid:\nDisabled:    true\nRoles:       role1 (priority: 20)\nGroups:      group1 (priority: 10)\n")

    # Set clientid
    ctrl_dynsec_cmd(["setClientID", "username1", "fixed-id"], ports)

    # Verify client
    ctrl_dynsec_cmd(["getClient", "username1"], ports, response="Username:    username1\nClientid:    fixed-id\nDisabled:    true\nRoles:       role1 (priority: 20)\nGroups:      group1 (priority: 10)\n")

    # Clear clientid
    ctrl_dynsec_cmd(["setClientID", "username1"], ports)

    # Enable client
    ctrl_dynsec_cmd(["enableClient", "username1"], ports)

    # Verify client
    ctrl_dynsec_cmd(["getClient", "username1"], ports, response="Username:    username1\nClientid:\nRoles:       role1 (priority: 20)\nGroups:      group1 (priority: 10)\n")

    # Set client password
    ctrl_dynsec_cmd(["setClientPassword", "username1", "new-password"], ports)
    ctrl_dynsec_cmd(["setClientPassword", "username1"], ports, input="not\nmatch\n")

    # Remove an ACL
    ctrl_dynsec_cmd(["removeRoleACL", "role1", "publishClientReceive", "#"], ports)
    ctrl_dynsec_cmd(["getRole", "role1"], ports, response="Rolename: role1\nACLs:     publishClientSend    : allow : # (priority: 1)\n          subscribeLiteral     : allow : # (priority: 1)\n          subscribePattern     : allow : # (priority: 2)\n          unsubscribeLiteral   : deny  : # (priority: 1)\n          unsubscribePattern   : deny  : # (priority: 2)\n")

    ctrl_dynsec_cmd(["removeRoleACL", "role1", "publishClientSend", "#"], ports)
    ctrl_dynsec_cmd(["getRole", "role1"], ports, response="Rolename: role1\nACLs:     subscribeLiteral     : allow : # (priority: 1)\n          subscribePattern     : allow : # (priority: 2)\n          unsubscribeLiteral   : deny  : # (priority: 1)\n          unsubscribePattern   : deny  : # (priority: 2)\n")

    ctrl_dynsec_cmd(["removeRoleACL", "role1", "subscribeLiteral", "#"], ports)
    ctrl_dynsec_cmd(["removeRoleACL", "role1", "subscribePattern", "#"], ports)
    ctrl_dynsec_cmd(["removeRoleACL", "role1", "unsubscribeLiteral", "#"], ports)
    ctrl_dynsec_cmd(["removeRoleACL", "role1", "unsubscribePattern", "#"], ports)
    ctrl_dynsec_cmd(["getRole", "role1"], ports, response="Rolename: role1\n")

    # Remove a Role
    ctrl_dynsec_cmd(["deleteRole", "role2"], ports)

    # Remove client from a group
    ctrl_dynsec_cmd(["removeGroupClient", "group1", "username1"], ports)

    # Remove role from a group
    ctrl_dynsec_cmd(["removeGroupRole", "group1", "role2"], ports)

    # Delete group
    ctrl_dynsec_cmd(["deleteGroup", "group1"], ports)

    ctrl_dynsec_cmd(["removeClientRole", "username1", "role1"], ports)

    # Delete client
    ctrl_dynsec_cmd(["deleteClient", "username1"], ports)

    rc = 0
except mosq_test.TestError:
    pass
finally:
    os.remove(conf_file)
    try:
        os.remove(f"{ports[0]}/dynamic-security.json")
        pass
    except FileNotFoundError:
        pass
    shutil.rmtree(f"{ports[0]}")
    broker.terminate()
    if mosq_test.wait_for_subprocess(broker):
        print("broker not terminated")
        if rc == 0: rc=1

exit(rc)
