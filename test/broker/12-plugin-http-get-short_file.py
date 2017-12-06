#!/usr/bin/env python

# Test a GET request to the http plugin, fetching a simple string reponse

import inspect, os, sys, requests
# From http://stackoverflow.com/questions/279237/python-import-a-module-from-a-folder
cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile( inspect.currentframe() ))[0],"..")))
if cmd_subfolder not in sys.path:
    sys.path.insert(0, cmd_subfolder)

import mosq_test

rc = 1
keepalive = 10
connect_packet = mosq_test.gen_connect("http-plugin-test-client", keepalive=keepalive)
connack_packet = mosq_test.gen_connack(rc=0)

broker_cmd = ['../../src/mosquitto', '-c', '12-plugin-http.conf']
broker = None

try:
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), cmd=broker_cmd)
    r = requests.get("http://localhost:8080/short.txt")
    r.raise_for_status()
    rc = len(r.text) != 5000
    if rc:
      print("got wrong text")
    else:
      with open('public_html/short.txt', 'r') as f:
        expected = f.read()
        if (expected != r.text):
          print("test file contents mismatch")
          rc = -1
      f.close()
    if (rc == 0):
      for n in range(1,5):
        key = "x-test{0}".format(n)
        val = "{0}{0}{0}".format(n)
        if (r.headers[key] == None or r.headers[key] != val):
          rc = -1
          break;
      #check the headers
except requests.exceptions.RequestException as E:
    print("HTTP Request failed:")
    print(E)
except IOError:
    print("Broker failed by exception")

if broker is not None:
    broker.terminate()
    broker.wait()

exit(rc)

