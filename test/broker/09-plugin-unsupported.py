#!/usr/bin/env python3

from mosq_test_helper import *

# Check whether unsupported plugin versions are handled ok

def write_config(filename, port, plugver):
    with open(filename, 'w') as f:
        f.write(f"listener {port}\n")
        f.write(f"auth_plugin {mosq_paths.test_plugin(f'bad_v{plugver}')}\n")
        f.write("allow_anonymous false\n")

def do_test(plugver):
    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port, plugver)

    try:
        rc = 1
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port, check_port=False)
        broker.wait(5)
        mosq_test.terminate_broker(broker)
        if broker.returncode == 13:
            rc = 0
    except mosq_test.TestError:
        pass
    finally:
        os.remove(conf_file)
        if rc:
            print(mosq_test.broker_log(broker))
            exit(rc)

do_test(1)
do_test(6)
