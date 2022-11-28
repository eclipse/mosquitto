#!/usr/bin/env python3

# mosquitto_ctrl broker

from mosq_test_helper import *
import json
import shutil

def write_config(filename, ports):
    with open(filename, 'w') as f:
        f.write("enable_control_api true\n")
        f.write(f"global_plugin {mosq_test.get_build_root()}/plugins/dynamic-security/mosquitto_dynamic_security.so\n")
        f.write(f"plugin_opt_config_file {ports[0]}/dynamic-security.json\n")
        f.write("allow_anonymous false\n")
        f.write(f"listener {ports[0]}\n")
        f.write(f"listener {ports[1]}\n")
        f.write(f"certfile {mosq_test.get_build_root()}/test/ssl/server.crt\n")
        f.write(f"keyfile {mosq_test.get_build_root()}/test/ssl/server.key\n")

def ctrl_cmd(cmd, args, ports, response=None):
    opts = ["-u", "admin",
            "-P", "admin",
            "-V", "5"]

    if response is None:
        opts += [
                "-p", str(ports[0]),
                "-q", "1"
                 ]
        capture_output = False
    else:
        opts += ["-p", str(ports[1])]
        opts += ["--cafile", f"{mosq_test.get_build_root()}/test/ssl/all-ca.crt"]
        capture_output = True

    proc = subprocess.run([mosq_test.get_build_root()+"/apps/mosquitto_ctrl/mosquitto_ctrl"]
                    + opts + [cmd] + args,
                    env=env, capture_output=True, encoding='utf-8')

    if response is not None:
        if proc.stdout != response:
            raise ValueError(proc.stdout)

    if proc.returncode != 0:
        raise ValueError(args)


rc = 0
ports = mosq_test.get_port(2)
conf_file = os.path.basename(__file__).replace('.py', '.conf')
write_config(conf_file, ports)

env = dict(os.environ)
env['LD_LIBRARY_PATH'] = mosq_test.get_build_root() + '/lib'

if not os.path.exists(str(ports[0])):
    os.mkdir(str(ports[0]))

# Generate initial dynsec file
ctrl_cmd("dynsec", ["init", f"{ports[0]}/dynamic-security.json", "admin", "admin"], ports)
ctrl_cmd("broker", ["help"], ports)

# Then start broker
broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=ports[0])

try:
    ctrl_cmd("dynsec", ["addRoleACL", "admin", "publishClientSend", "$CONTROL/#", "allow"], ports)
    ctrl_cmd("dynsec", ["addRoleACL", "admin", "publishClientReceive", "$CONTROL/#", "allow"], ports)
    ctrl_cmd("dynsec", ["addRoleACL", "admin", "subscribePattern", "$CONTROL/#", "allow"], ports)

    ctrl_cmd("broker", ["listListeners"], ports, response=f"Listener 1:\n  Port:              {ports[0]}\n  Protocol:          mqtt\n  TLS:               false\n\nListener 1:\n  Port:              {ports[1]}\n  Protocol:          mqtt\n  TLS:               true\n\n")

    ctrl_cmd("broker", ["listPlugins"], ports, response="Plugin:            dynamic-security\nControl endpoints: $CONTROL/dynamic-security/v1\n")

    rc = 0
except mosq_test.TestError:
    pass
except Exception as err:
    print(err)
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
    (_, stde) = broker.communicate()
    if rc:
        print(stde.decode('utf-8'))


exit(rc)
