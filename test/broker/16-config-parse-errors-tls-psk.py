#!/usr/bin/env python3

# Test whether config parse errors are handled

from mosq_test_helper import *

vg_index = 0

def write_config(filename, port, config_str):
    with open(filename, 'w') as f:
        f.write(f"{config_str}")


def do_test(config_str, rc_expected):
    rc = 1
    port = mosq_test.get_port()

    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port, config_str)

    try:
        broker = mosq_test.start_broker(conf_file, check_port=False)
        broker.wait(timeout=1)

        if broker.returncode == rc_expected:
            rc = 0
    except mosq_test.TestError:
        pass
    except subprocess.TimeoutExpired:
        broker.terminate()
    except Exception as e:
        print(e)
    finally:
        os.remove(conf_file)
        (stdo, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
            print(config_str)
            exit(rc)


do_test("bridge_psk string\n", 3) # Missing bridge config
do_test("bridge_identity string\n", 3) # Missing bridge config


exit(0)
