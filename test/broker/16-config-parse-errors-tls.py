#!/usr/bin/env python3

# Test whether config parse errors are handled

from mosq_test_helper import *

vg_index = 0

def write_config(filename, port, config_str):
    with open(filename, 'w') as f:
        f.write(f"{config_str}")


def do_test(config_str, rc_expected):
    rc = 1

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


port = mosq_test.get_port()
do_test("bridge_cafile string\n", 3) # Missing bridge config
do_test("bridge_alpn string\n", 3) # Missing bridge config
do_test("bridge_ciphers string\n", 3) # Missing bridge config
do_test("bridge_ciphers_tls1.3 string\n", 3) # Missing bridge config
do_test("bridge_capath string\n", 3) # Missing bridge config
do_test("bridge_certfile string\n", 3) # Missing bridge config
do_test("bridge_keyfile string\n", 3) # Missing bridge config
do_test("bridge_tls_version string\n", 3) # Missing bridge config

do_test(f"listener {port}\ncertfile\n", 3) # empty certfile
do_test(f"listener {port}\nkeyfile\n", 3) # empty keyfile

do_test(f"listener {port}\ncertfile ./16-config-parse-errors.py\nkeyfile ../ssl/server.key\n", 1) # invalid certfile
do_test(f"listener {port}\ncertfile ../ssl/server.crt\nkeyfile ./16-config-parse-errors.py\n", 1) # invalid keyfile
do_test(f"listener {port}\ncertfile ../ssl/server.crt\nkeyfile ../ssl/client.key\n", 1) # mismatched certfile / keyfile

do_test(f"listener {port}\ncertfile ../ssl/server.crt\nkeyfile ../ssl/server.key\ntls_version invalid\n", 1) # invalid tls_version

do_test(f"listener {port}\ncertfile ../ssl/server.crt\nkeyfile ../ssl/server.key\ncrlfile invalid\n", 1) # missing crl file
do_test(f"listener {port}\ncertfile ../ssl/server.crt\nkeyfile ../ssl/server.key\ndhparamfile invalid\n", 1) # missing dh param file
do_test(f"listener {port}\ncertfile ../ssl/server.crt\nkeyfile ../ssl/server.key\ndhparamfile ./16-config-parse-errors.py\n", 1) # invalid dh param file

do_test(f"listener {port}\ncertfile ../ssl/server.crt\nkeyfile ../ssl/server.key\nciphers invalid\n", 1) # invalid ciphers
do_test(f"listener {port}\ncertfile ../ssl/server.crt\nkeyfile ../ssl/server.key\nciphers_tls1.3 invalid\n", 1) # invalid ciphers_tls1.3

exit(0)
