#!/usr/bin/env python3

# Test whether command line args are handled

from mosq_test_helper import *

vg_index = 0

def start_broker(args):
    global vg_index
    cmd = [mosq_test.get_build_root() + '/src/mosquitto'] + args

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


def do_test(args, rc_expected):
    rc = 1
    port = mosq_test.get_port()

    try:
        broker = start_broker(args)
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
        (stdo, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
            exit(rc)


do_test(["-h"], 3)
do_test(["-p", "0"], 3) # Port invalid
do_test(["-p", "65536"], 3) # Port invalid
do_test(["-p"], 3) # Missing port
do_test(["-c"], 3) # Missing config
do_test(["--tls-keylog"], 3) # Missing filename
do_test(["--unknown"], 3) # Unknown option

exit(0)
