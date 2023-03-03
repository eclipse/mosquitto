#!/usr/bin/env python3

# Test whether a plugin can subscribe to the tick event

from mosq_test_helper import *
import signal

def write_config1(filename, ports, per_listener_settings, plugver):
    with open(filename, 'w') as f:
        f.write("per_listener_settings %s\n" % (per_listener_settings))
        f.write("plugin_load auth c/auth_plugin_v%d.so\n" % (plugver))
        f.write("listener %d\n" % (ports[0]))
        f.write("plugin_use auth\n")
        f.write("listener %d\n" % (ports[1]))
        f.write("allow_anonymous false\n")
        f.write("listener %d\n" % (ports[2]))
        f.write("plugin_use auth\n")

def write_config2(filename, ports, per_listener_settings, plugver):
    with open(filename, 'w') as f:
        f.write("per_listener_settings %s\n" % (per_listener_settings))
        f.write("plugin_load auth c/auth_plugin_v%d.so\n" % (plugver))
        f.write("listener %d\n" % (ports[0]))
        f.write("listener %d\n" % (ports[1]))
        f.write("plugin_use auth\n")
        f.write("listener %d\n" % (ports[2]))
        f.write("plugin_use auth\n")

def client_check(username, password, rc, port):
    connect_packet = mosq_test.gen_connect(client_id="id", username=username, password=password)
    connack_packet = mosq_test.gen_connack(rc=rc)
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
    sock.close()


def do_test(per_listener_settings, plugver):
    proto_ver = 5
    ports = mosq_test.get_port(3)
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config1(conf_file, ports, per_listener_settings, plugver)

    plugin_reload_fixed = False # FIXME - set to true then remove once plugin reloading is working

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=ports[0])

    rc = 1
    try:
        client_check("test-username", "cnwTICONIURW", 0, ports[0]) # Should succeed
        client_check("test-username", "cnwTICONIURW", 5, ports[1]) # Should fail
        client_check("test-username", "cnwTICONIURW", 0, ports[2]) # Should succeed

        client_check("bad-actor", "nope", 5, ports[0]) # Should fail
        client_check("bad-actor", "nope", 5, ports[1]) # Should fail
        client_check("bad-actor", "nope", 5, ports[2]) # Should fail

        client_check(None, None, 5, ports[0]) # Should fail
        client_check(None, None, 5, ports[1]) # Should fail
        client_check(None, None, 5, ports[2]) # Should fail

        if plugin_reload_fixed:
            # Now swap auth around so ports[0] has no plugin but ports[1] does
            write_config2(conf_file, ports, per_listener_settings, plugver)

            broker.send_signal(signal.SIGHUP)

            client_check("test-username", "cnwTICONIURW", 5, ports[0]) # Should fail
            client_check("test-username", "cnwTICONIURW", 0, ports[1]) # Should succeed
            client_check("test-username", "cnwTICONIURW", 0, ports[2]) # Should succeed

            client_check("bad-actor", "nope", 5, ports[0]) # Should fail
            client_check("bad-actor", "nope", 5, ports[1]) # Should fail
            client_check("bad-actor", "nope", 5, ports[2]) # Should fail

            client_check(None, None, 5, ports[0]) # Should fail
            client_check(None, None, 5, ports[1]) # Should fail
            client_check(None, None, 5, ports[2]) # Should fail
        else:
            # Now swap auth around so ports[0] has no plugin but ports[1] does
            write_config2(conf_file, ports, per_listener_settings, plugver)

            # Check config works as before - plugin reloading disabled

            broker.send_signal(signal.SIGHUP)

            client_check("test-username", "cnwTICONIURW", 0, ports[0]) # Should succeed
            client_check("test-username", "cnwTICONIURW", 5, ports[1]) # Should fail
            client_check("test-username", "cnwTICONIURW", 0, ports[2]) # Should succeed

            client_check("bad-actor", "nope", 5, ports[0]) # Should fail
            client_check("bad-actor", "nope", 5, ports[1]) # Should fail
            client_check("bad-actor", "nope", 5, ports[2]) # Should fail

            client_check(None, None, 5, ports[0]) # Should fail
            client_check(None, None, 5, ports[1]) # Should fail
            client_check(None, None, 5, ports[2]) # Should fail

        rc = 0
    except Exception as err:
        print(err)
    finally:
        os.remove(conf_file)
        broker.terminate()
        broker.wait()
        if rc:
            print(f"per_listener_settings:{per_listener_settings} plugver:{plugver}")
            (stdo, stde) = broker.communicate()
            print(stde.decode('utf-8'))
            exit(rc)

print("T1")
do_test("false", 2)
print("T2")
do_test("true", 2)
print("T3")
do_test("false", 3)
print("T4")
do_test("true", 3)
print("T5")
do_test("false", 4)
print("T6")
do_test("true", 4)
print("T7")
do_test("false", 5)
print("T8")
do_test("true", 5)
