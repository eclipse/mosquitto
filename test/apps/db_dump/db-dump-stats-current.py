#!/usr/bin/env python3

# Check whether output from the current broker can be read by the current db_dump.

from mosq_test_helper import *
import shutil

def write_config(conf_file, port):
    with open(conf_file, 'w') as f:
        f.write(f"listener {port}\n")
        f.write("allow_anonymous true\n")
        f.write("persistence true\n")
        f.write(f"persistence_location {port}\n")

def check_db(port, counts):
    stdout = f"DB_CHUNK_CFG:        {counts[0]}\n" + \
        f"DB_CHUNK_BASE_MSG:   {counts[1]}\n" + \
        f"DB_CHUNK_CLIENT_MSG: {counts[2]}\n" + \
        f"DB_CHUNK_RETAIN:     {counts[3]}\n" + \
        f"DB_CHUNK_SUB:        {counts[4]}\n" + \
        f"DB_CHUNK_CLIENT:     {counts[5]}\n"

    cmd = [
        mosq_test.get_build_root()+'/apps/db_dump/mosquitto_db_dump',
        '--stats',
        f'{port}/mosquitto.db'
    ]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1, encoding='utf-8')
    if res.stdout != stdout:
        print(res.stdout)
        raise mosq_test.TestError


def do_test(counts):
    rc = 1

    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')

    try:
        if not os.path.exists(str(port)):
            os.mkdir(str(port))
    except FileExistsError:
        pass
    write_config(conf_file, port)

    try:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port, use_conf=True)
        env = {
            'LD_LIBRARY_PATH': mosq_test.get_build_root() + '/lib',
            'XDG_CONFIG_HOME':'/tmp/missing'
            }

        # Set up persistent client session, including a subscription
        cmd = [
            mosq_test.get_build_root()+'/client/mosquitto_sub',
            '-c',
            '-i', 'client-id',
            '-p', str(port),
            '-q', '1',
            '-t', 'sub-topic',
            '-E'
        ]
        subprocess.run(cmd, timeout=1, env=env)

        # Publish a retained message which is also queued for the subscriber
        cmd = [
            mosq_test.get_build_root()+'/client/mosquitto_pub',
            '-p', str(port),
            '-q', '1',
            '-t', 'sub-topic',
            '-m', 'message',
            '-r'
        ]
        subprocess.run(cmd, timeout=1, env=env)

        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            raise mosq_test.TestError
        check_db(port, counts)
        rc = 0

    except Exception as e:
        print(e)
    finally:
        os.remove(conf_file)
        os.remove(f"{port}/mosquitto.db")
        shutil.rmtree(str(port))
        if broker is not None:
            broker.terminate()

    exit(rc)

do_test([1,1,1,1,1,1])
