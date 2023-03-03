#!/usr/bin/env python3

from mosq_test_helper import *

# Check whether incomplete plugins are handled ok

def write_config(filename, port, plugver, num):
    with open(filename, 'w') as f:
        f.write(f"listener {port}\n")
        f.write(f"auth_plugin c/bad_v{plugver}_{num}.so\n")
        f.write("allow_anonymous false\n")

def do_test(plugver, num):
    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port, plugver, num)

    try:
        rc = 1
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port, check_port=False)
        broker.wait(1)
        broker.terminate()
        if broker.returncode == 13:
            rc = 0
    except mosq_test.TestError:
        pass
    finally:
        os.remove(conf_file)
        (stdo, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
            exit(rc)

do_test("none", 1)

for i in range(1,8):
    do_test(2, i)

for i in range(1,8):
    do_test(3, i)

for i in range(1,5):
    do_test(4, i)

do_test(5, 1)
