#!/usr/bin/env python3

# Test whether connections to a unix socket work

from mosq_test_helper import *

vg_index = 0
def start_broker(filename):
    global vg_index
    cmd = ['../../src/mosquitto', '-v', '-c', filename]

    if os.environ.get('MOSQ_USE_VALGRIND') is not None:
        logfile = os.path.basename(__file__)+'.'+str(vg_index)+'.vglog'
        if os.environ.get('MOSQ_USE_VALGRIND') == 'callgrind':
            cmd = ['valgrind', '-q', '--tool=callgrind', '--log-file='+logfile] + cmd
        elif os.environ.get('MOSQ_USE_VALGRIND') == 'massif':
            cmd = ['valgrind', '-q', '--tool=massif', '--log-file='+logfile] + cmd
        else:
            cmd = ['valgrind', '-q', '--trace-children=yes', '--leak-check=full', '--show-leak-kinds=all', '--log-file='+logfile] + cmd

    vg_index += 1
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener 0 %d.sock\n" % (port))
        f.write("allow_anonymous true\n")

def do_test():
    rc = 1

    connect_packet = mosq_test.gen_connect("unix-socket")
    connack_packet = mosq_test.gen_connack(rc=0)

    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port)
    broker = start_broker(filename=conf_file)

    try:
        if os.environ.get('MOSQ_USE_VALGRIND') is None:
            time.sleep(0.1)
        else:
            time.sleep(2)
        sock = mosq_test.do_client_connect_unix(connect_packet, connack_packet, path=f"{port}.sock")
        sock.close()

        rc = 0
    except mosq_test.TestError:
        pass
    except Exception as err:
        print(err)
    finally:
        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1
        os.remove(conf_file)
        try:
            os.remove(f"{port}.sock")
        except FileNotFoundError:
            pass
        (stdo, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
            exit(rc)

do_test()
exit(0)
