import inspect, os, sys

# From http://stackoverflow.com/questions/279237/python-import-a-module-from-a-folder
cmd_subfolder = os.path.realpath(
    os.path.abspath(
        os.path.join(os.path.split(inspect.getfile(inspect.currentframe()))[0], "..")
    )
)
if cmd_subfolder not in sys.path:
    sys.path.insert(0, cmd_subfolder)

import mosq_paths
import mosq_test
import mqtt5_opts
import mqtt5_props
import mqtt5_rc
import mqtt_packets
from mosquitto_broker import MosquittoBroker

import socket
import ssl
import struct
import subprocess
import time
import errno
import traceback
from pathlib import Path

source_dir = Path(__file__).resolve().parent
ssl_dir = source_dir.parent / "ssl"

import importlib


def persist_module():
    if len(sys.argv) > 1:
        mod = sys.argv.pop(1).replace(".py", "")
    else:
        raise RuntimeError("Not enough command line arguments - need persist module")
    return importlib.import_module(mod)


def do_test_broker_failure(
    conf_file: str,
    config: list,
    port: int,
    rc_expected: int,
    error_log_entry: str = None,
    stdout_entry: str = None,
    cmd_args: list = [],
    with_test_config: bool = True,
):
    rc = 1

    use_conf_file = len(conf_file) > 0

    cmd_args = cmd_args.copy()
    if with_test_config and use_conf_file:
        cmd_args.insert(0, "--test-config")

    create_conf_file = use_conf_file and len(config)
    if create_conf_file:
        with open(conf_file, "w") as f:
            f.write("\n".join(config))
            f.write("\n")
    try:
        broker = None
        broker = mosq_test.start_broker(
            conf_file,
            port=port,
            use_conf=use_conf_file,
            expect_fail=True,
            cmd_args=cmd_args,
        )
        stde = mosq_test.broker_log(broker)
        if broker.returncode != rc_expected:
            print(f"Expected broker return code {rc_expected}, got {broker.returncode}")
            print(stde)
            return rc

        if error_log_entry is not None:
            error_log = stde
            if error_log_entry not in error_log:
                print(
                    f"Error log entry: '{error_log_entry}' not found in '{error_log}'"
                )
                return rc

        if stdout_entry is not None:
            (stdo, _) = broker.communicate()
            stdout_log = stdo.decode("utf-8")
            if stdout_entry not in stdout_log:
                print(
                    f"Error stdout entry: '{stdout_entry}' not found in '{stdout_log}'"
                )
                return rc

        rc = 0
    except subprocess.TimeoutExpired:
        if broker is not None:
            mosq_test.wait_for_subprocess(broker, timeout=1)
        return rc
    except Exception as e:
        print(e)
        return rc
    finally:
        if create_conf_file:
            try:
                os.remove(conf_file)
            except FileNotFoundError:
                pass
        if rc:
            print(
                f"While testing 'config {chr(10).join(config) if len(config) else ''}'{', args '+ ' '.join(cmd_args) if cmd_args is not None else ''}"
            )
            exit(rc)

    return rc
