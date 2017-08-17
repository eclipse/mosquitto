#!/usr/bin/env python
# MQTT version 5 tests.
base_dir = '/home/centos/paho.mqtt.testing/interoperability/'
test_filename = 'client_test5.py'

import inspect, os, sys, subprocess, distutils.spawn

try:
    assert(distutils.spawn.find_executable('python3'))
except:
    print("WARNING: python3 not available, skipping mqttv5 test.")
    exit(0)

try:
    assert(os.path.exists(base_dir + test_filename))
except:
    print("WARNING: paho.mqtt.testing module not available, skipping mqttv5 test.")
    print("Preparing test environment:")
    print("  $ git clone https://github.com/eclipse/paho.mqtt.testing/")
    print("  $ cd paho.mqtt.testing")
    print("  $ git checkout -b mqttv5 origin/mqttv5")
    print("  and set proper base_dir in mosquitto's 12-mqttv5_test.py")
    exit(0)

# From http://stackoverflow.com/questions/279237/python-import-a-module-from-a-folder
cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile( inspect.currentframe() ))[0],"..")))
if cmd_subfolder not in sys.path:
    sys.path.insert(0, cmd_subfolder)

import mosq_test

availabe_test = [
    'test_basic',
    'test_retained_message',
    'test_zero_length_clientid',
    'test_overlapping_subscriptions',
    'test_redelivery_on_reconnect',
    'test_dollar_topics',
    'test_user_properties',
    'test_payload_format',
    'test_request_response']

for i in availabe_test:
    rc = 1
    print('mqttv5 ' + i)
    cmd = ['../../src/mosquitto', '-p', '1883']
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), cmd=cmd, port=1883)

    try:
        subprocess.check_call(['python3', base_dir + test_filename, 'Test.' + i], cwd = base_dir)
        rc = 0
    finally:
        broker.terminate()
        broker.wait()
        if rc:
            (stdo, stde) = broker.communicate()
            print(stde)
            exit(rc)

exit(rc)


