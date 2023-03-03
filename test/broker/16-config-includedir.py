#!/usr/bin/env python3

# Test whether include_dir works properly

from mosq_test_helper import *

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write(f"include_dir {port}\n")
    os.mkdir(str(port))
    with open(f"{port}/1.conf", 'w') as f:
        f.write(f"listener {port}\n")
    with open(f"{port}/2.conf", 'w') as f:
        f.write(f"allow_anonymous true\n")


def do_test():
    port = mosq_test.get_port()

    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port)

    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    try:
        rc = 1
        connect_packet = mosq_test.gen_connect("connect-include-dir")
        connack_packet = mosq_test.gen_connack(rc=0)

        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        sock.close()
        rc = 0
    except mosq_test.TestError:
        pass
    except Exception as e:
        print(e)
    finally:
        os.remove(conf_file)
        os.remove(f"{port}/1.conf")
        os.remove(f"{port}/2.conf")
        os.rmdir(f"{port}")
        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1
        (stdo, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
            exit(rc)


do_test()

exit(0)
