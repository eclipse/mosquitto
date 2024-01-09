#!/usr/bin/env python3

# Connect a client, start a QoS 2 flow, disconnect, restore, carry on with the
# QoS 2 flow. Is it received?

from mosq_test_helper import *

persist_help = persist_module()

port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace(".py", ".conf")
persist_help.write_config(conf_file, port)



def do_success_test(create_db_of_version: list[int]):
    print(f"db migration success test from db {create_db_of_version}")
    persist_help.init(port, create_db_of_version=create_db_of_version)

    rc = 1

    broker = mosq_test.start_broker(
        filename=os.path.basename(__file__), use_conf=True, port=port
    )
    try:
        # Kill broker
        (broker_terminate_rc, stde) = mosq_test.terminate_broker(broker)
        broker = None

        persist_help.check_version_infos(port, database_schema_version=[1, 0, 0])

        rc = 0
    finally:
        if broker is not None:
            broker.terminate()
            if mosq_test.wait_for_subprocess(broker):
                print("broker not terminated")
                if rc == 0:
                    rc = 1
                (_, stde) = broker.communicate()

        rc += persist_help.cleanup(port)

        if rc:
            print(stde.decode("utf-8"))
            exit(rc)


def do_failure_test(create_db_of_version: list[int]):
    print(f"db migration failure test for db {create_db_of_version}")
    persist_help.init(port, create_db_of_version=create_db_of_version)

    rc = 1
    try:
        rc = do_test_broker_failure(
            conf_file=conf_file,
            config=[],
            port=port,
            rc_expected=3,
            error_log_entry=f"Unknown database_schema version {'.'.join([str(i) for i in create_db_of_version])}",
        )
    except Exception as exc:
        print(f"Exception: {str(exc)}")
    finally:
        rc += persist_help.cleanup(port)
        if rc:
            exit(rc)


do_success_test(create_db_of_version=None)
do_success_test(create_db_of_version=[0, 9, 0])
do_success_test(create_db_of_version=[1, 0, 0])

do_failure_test(create_db_of_version=[1, 1, 0])
do_failure_test(create_db_of_version=[2, 0, 0])

os.remove(conf_file)
