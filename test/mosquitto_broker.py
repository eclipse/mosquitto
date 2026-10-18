"""
"""

from subprocess import Popen
from typing import Optional, Union

import logging
import os

import mosq_test

from broker_config import BrokerConfig

class MosquittoBroker:
    def __init__(
        self,
        port: Optional[int] = None,
        config: Union[None, BrokerConfig, str, list, dict] = None,
        config_file_name=None,
        add_port_to_config=True,
        remove_files=True,
        env=None,
        termination_timeout = 10,
        expect_fail=False,
        check_port=True,
        cmd_args=None,
    ):
        assert port is not None or (isinstance(config, BrokerConfig))
        if isinstance(config, BrokerConfig):
            self._port = config.listeners[0].port if len(config.listeners) > 0 else port
        else:
            self._port = port

        self._process :Optional[Popen]= None
        self.env = env
        self.check_port = check_port
        self.cmd_args = cmd_args
        if config_file_name is None or config_file_name == "":
            config_file_name = f"{str(self._port)}.conf"
        self._config_file_name = config_file_name
        self._config_files = set()
        self._expect_fail = expect_fail
        self._extra_files = set()
        self._remove_files = remove_files
        self._termination_timeout = termination_timeout
        if config:
            if (
                not isinstance(config, BrokerConfig)
                and add_port_to_config
                and self._port
            ):
                self.add_config(f"listener {self._port}\n")
            self.add_config(config)

    def __str__(self):
        return f"{self.__class__.__name__}:{self._port}"

    @property
    def port(self):
        return self._port

    @property
    def process(self):
        if self._process is None:
            raise RuntimeError("process not started yet")
        return self._process

    def set_remove_files(self, value: bool):
        self._remove_files = value

    def add_config(self, config, file_name=None):
        if isinstance(config, dict):
            config = "\n".join(f"{k} {v}" for k, v in config.items())
        if isinstance(config, list):
            config = "\n".join(f"{k} {v}" for k, v in config)
        if isinstance(config, BrokerConfig):
            config = str(config)
        if file_name is None or file_name == "":
            file_name = self._config_file_name
        file_mode = "w"
        if file_name in self._config_files:
            file_mode = "a"
        else:
            self._config_files.add(file_name)
        logging.debug(f"{self} Write to config file {file_name} with mode {file_mode}")
        with open(file_name, file_mode) as config_file:
            config_file.writelines(config)

    def add_extra_file(self, file_name):
        self._extra_files.add(file_name)

    def start(self, expect_fail=False, start_timeout=0.1):
        logging.info(f"Starting {self}")
        self._process = mosq_test.start_broker(
            use_conf=len(self._config_files) > 0,
            filename=self._config_file_name,
            port=self._port,
            env=self.env,
            expect_fail=expect_fail,
            check_port=self.check_port,
            timeout=start_timeout,
            cmd_args=self.cmd_args,
        )
        logging.info(f"{self} "+ "Started" if self.is_running() else f"Terminated rc={self._process.returncode}")

    def is_running(self):
        return self._process and self._process.poll() is None

    def check_log(self, matcher):
        if not matcher(self.get_log()):
            raise AssertionError(f"{matcher.last_message}")
        else:
            logging.info(f"{self} Check log {matcher}")

    def get_log(self):
        return mosq_test.broker_log(self._process)

    def terminate(self):
        if self._process:
            mosq_test.terminate_broker(self._process)

    def reload(self):
        if self._process:
            mosq_test.reload_broker(self._process)

    def __enter__(self):
        if self._process == None:
            self.start()
        return self

    def __exit__(self, ex_type, value, tb):
        self.stop(ex_type)

    def stop(self, ex_type=None):
        if self._process:
            timed_out, _ = mosq_test.terminate_broker(self._process)
            logging.info(f"Stopping {self}")
            logging.info(f"Stopped {self}")
            if ex_type is not None or timed_out or (self._expect_fail == False and self._process.returncode != 0):
                print(f"\n{self} log:")
                print(self.get_log())
            else:
                logging.debug(f"\n{self} log:")
                logging.debug(self.get_log())
            if timed_out:
                raise RuntimeError(f"{self} timed out when shutting down")
            if self._expect_fail == False and self._process.returncode != 0:
                raise RuntimeError(f"{self} exited with {self._process.returncode}")

        if self._remove_files:
            for file_name in self._config_files:
                os.remove(file_name)
            for file_name in self._extra_files:
                try:
                    os.remove(file_name)
                except FileNotFoundError:
                    pass
