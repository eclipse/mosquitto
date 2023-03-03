#!/usr/bin/env python3

# Test for CVE-2018-xxxxx.

from mosq_test_helper import *
import signal

def write_config(filename, port, per_listener):
    with open(filename, 'w') as f:
        f.write("per_listener_settings %s\n" % (per_listener))
        f.write("listener %d\n" % (port))
        f.write("password_file %s\n" % (filename.replace('.conf', '.pwfile')))
        f.write("allow_anonymous false")

def write_pwfile(filename, bad_line1, bad_line2):
    with open(filename, 'w') as f:
        if bad_line1 is not None:
            f.write('%s\n' % (bad_line1))
        # Username test, password test
        f.write('test:$6$njERlZMi/7DzNB9E$iiavfuXvUm8iyDZArTy7smTxh07GXXOrOsqxfW6gkOYVXHGk+W+i/8d3xDxrMwEPygEBhoA8A/gjQC0N2M4Lkw==\n')
        # Username empty, password 0 length
        f.write('empty:$6$o+53eGXtmlfHeYrg$FY7X9DNQ4uU1j0NiPmGOOSU05ZSzhqNmNhXIof/0nLpVb1zDhcRHdaC72E3YryH7dtTiG/r6jH6C8J+30cZBgA==\n')
        if bad_line2 is not None:
            f.write('%s\n' % (bad_line2))

def do_test(port, connack_rc, username, password):
    rc = 1
    connect_packet = mosq_test.gen_connect("username-password-check", username=username, password=password)
    connack_packet = mosq_test.gen_connack(rc=connack_rc)

    try:
        sock = mosq_test.do_client_connect(connect_packet, connack_packet, port=port)
        rc = 0
        sock.close()
    except mosq_test.TestError:
        pass
    finally:
        if rc:
            raise AssertionError


def username_password_tests(port):
    broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

    try:
        do_test(port, connack_rc=0, username='test', password='test')
        do_test(port, connack_rc=5, username='test', password='bad')
        do_test(port, connack_rc=5, username='test', password='')
        do_test(port, connack_rc=5, username='test', password=None)
        do_test(port, connack_rc=5, username='empty', password='test')
        do_test(port, connack_rc=5, username='empty', password='bad')
        do_test(port, connack_rc=5, username='empty', password='')
        do_test(port, connack_rc=5, username='empty', password=None)
        do_test(port, connack_rc=5, username='bad', password='test')
        do_test(port, connack_rc=5, username='bad', password='bad')
        do_test(port, connack_rc=5, username='bad', password='')
        do_test(port, connack_rc=5, username='bad', password=None)
        do_test(port, connack_rc=5, username='', password='test')
        do_test(port, connack_rc=5, username='', password='bad')
        do_test(port, connack_rc=5, username='', password='')
        do_test(port, connack_rc=5, username='', password=None)
        do_test(port, connack_rc=5, username=None, password='test')
        do_test(port, connack_rc=5, username=None, password='bad')
        do_test(port, connack_rc=5, username=None, password='')
        do_test(port, connack_rc=5, username=None, password=None)
    except ValueError:
        pass
    finally:
        broker.terminate()
        if mosq_test.wait_for_subprocess(broker):
            print("broker not terminated")
            if rc == 0: rc=1


def all_tests(port):
    # Valid file, single user
    write_pwfile(pw_file, bad_line1=None, bad_line2=None)
    username_password_tests(port)

    # Invalid file, first line blank
    write_pwfile(pw_file, bad_line1='', bad_line2=None)
    username_password_tests(port)

    # Invalid file, last line blank
    write_pwfile(pw_file, bad_line1=None, bad_line2='')
    username_password_tests(port)

    # Invalid file, first and last line blank
    write_pwfile(pw_file, bad_line1='', bad_line2='')
    username_password_tests(port)

    # Invalid file, first line 'comment'
    write_pwfile(pw_file, bad_line1='#comment', bad_line2=None)
    username_password_tests(port)

    # Invalid file, last line 'comment'
    write_pwfile(pw_file, bad_line1=None, bad_line2='#comment')
    username_password_tests(port)

    # Invalid file, first and last line 'comment'
    write_pwfile(pw_file, bad_line1='#comment', bad_line2='#comment')
    username_password_tests(port)

    # Invalid file, first line blank and last line 'comment'
    write_pwfile(pw_file, bad_line1='', bad_line2='#comment')
    username_password_tests(port)

    # Invalid file, first line incomplete
    write_pwfile(pw_file, bad_line1='bad:', bad_line2=None)
    username_password_tests(port)

    # Invalid file, first line incomplete, but with "password"
    write_pwfile(pw_file, bad_line1='bad:bad', bad_line2=None)
    username_password_tests(port)

    # Invalid file, first line incomplete, partial password hash
    write_pwfile(pw_file, bad_line1='bad:$', bad_line2=None)
    username_password_tests(port)

    # Invalid file, first line incomplete, partial password hash
    write_pwfile(pw_file, bad_line1='bad:$6', bad_line2=None)
    username_password_tests(port)

    # Invalid file, first line incomplete, partial password hash
    write_pwfile(pw_file, bad_line1='bad:$6$', bad_line2=None)
    username_password_tests(port)

    # Valid file, first line incomplete, has valid salt but no password hash
    write_pwfile(pw_file, bad_line1='bad:$6$njERlZMi/7DzNB9E', bad_line2=None)
    username_password_tests(port)

    # Valid file, first line incomplete, has valid salt but no password hash
    write_pwfile(pw_file, bad_line1='bad:$6$njERlZMi/7DzNB9E$', bad_line2=None)
    username_password_tests(port)

    # Valid file, first line has invalid hash designator
    write_pwfile(pw_file, bad_line1='bad:$5$njERlZMi/7DzNB9E$iiavfuXvUm8iyDZArTy7smTxh07GXXOrOsqxfW6gkOYVXHGk+W+i/8d3xDxrMwEPygEBhoA8A/gjQC0N2M4Lkw==', bad_line2=None)
    username_password_tests(port)

    # Invalid file, missing username but valid password hash
    write_pwfile(pw_file, bad_line1=':$6$njERlZMi/7DzNB9E$iiavfuXvUm8iyDZArTy7smTxh07GXXOrOsqxfW6gkOYVXHGk+W+i/8d3xDxrMwEPygEBhoA8A/gjQC0N2M4Lkw==', bad_line2=None)
    username_password_tests(port)

    # Valid file, valid username but password salt not base64
    write_pwfile(pw_file, bad_line1='bad:$6$njER{ZMi/7DzNB9E$iiavfuXvUm8iyDZArTy7smTxh07GXXOrOsqxfW6gkOYVXHGk+W+i/8d3xDxrMwEPygEBhoA8A/gjQC0N2M4Lkw==', bad_line2=None)
    username_password_tests(port)

    # Valid file, valid username but password hash not base64
    write_pwfile(pw_file, bad_line1='bad:$6$njERlZMi/7DzNB9E$iiavfuXv{}8iyDZArTy7smTxh07GXXOrOsqxfW6gkOYVXHGk+W+i/8d3xDxrMwEPygEBhoA8A/gjQC0N2M4Lkw==', bad_line2=None)
    username_password_tests(port)



port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
pw_file = os.path.basename(__file__).replace('.py', '.pwfile')

try:
    write_config(conf_file, port, "false")
    all_tests(port)

    write_config(conf_file, port, "true")
    all_tests(port)
finally:
    os.remove(conf_file)
    os.remove(pw_file)

sys.exit(0)
