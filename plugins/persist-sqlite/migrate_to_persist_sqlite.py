#!/usr/bin/env python3
"""
Migration script to migrate from Snapshot persistence to Persist SQLite Plugin.
"""

import argparse
import base64
import json
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path  # use Path to be able to handle Windows as well
from typing import Self


# Snapshot persistence


class SnapshotPersistence:
    def __init__(self, json_dump: str):
        j_snapshot_persistence = json.loads(json_dump)

        self.base_messages: list[dict] = j_snapshot_persistence["base-messages"]
        self.clients: list[dict] = j_snapshot_persistence["clients"]
        self.client_messages: list[dict] = j_snapshot_persistence["client-messages"]
        self.retained_messages: list[dict] = j_snapshot_persistence["retained-messages"]
        self.subscriptions: list[dict] = j_snapshot_persistence["subscriptions"]


# SQlite3 DB


class SQLite3Persistence:
    def __init__(self):
        self.__store_id_topic_map: dict[int, str] = {}
        self.__db_path: Path = Path(__file__).parent.resolve() / "mosquitto.sqlite3"
        self.__conn: sqlite3.Connection = None
        self.__cursor: sqlite3.Cursor = None

        self.__init_db()

    def __del__(self):
        self.__close_db()

    def __close_db(self):
        if self.__cursor is not None:
            self.__cursor.close()

        if self.__conn is not None:
            self.__conn.commit()
            self.__conn.close()

    def __on_error(self):
        self.__close_db()
        self.__db_path.unlink(missing_ok=True)
        sys.exit(1)

    def __init_db(self):
        try:
            self.__conn = sqlite3.connect(self.__db_path)
            self.__cursor = self.__conn.cursor()

            self.__create_tables()
            self.__create_indices()
        except sqlite3.Error as err:
            print(f"Error during SQLite3 DB initialization. Reason: {str(err)}")
            self.__on_error()

    def __create_clients_table(self):
        self.__cursor.execute(
            "CREATE TABLE IF NOT EXISTS clients "
            "("
            "client_id TEXT PRIMARY KEY,"
            "username TEXT,"
            "connection_time INT64,"
            "will_delay_time INT64,"
            "session_expiry_time INT64,"
            "listener_port INT,"
            "max_packet_size INT,"
            "max_qos INT,"
            "retain_available INT,"
            "session_expiry_interval INT,"
            "will_delay_interval INT"
            ");",
        )

    def __create_client_msgs_table(self):
        self.__cursor.execute(
            "CREATE TABLE IF NOT EXISTS client_msgs "
            "("
            "client_id TEXT NOT NULL,"
            "cmsg_id INT64,"
            "store_id INT64,"
            "dup INTEGER,"
            "direction INTEGER,"
            "mid INTEGER,"
            "qos INTEGER,"
            "retain INTEGER,"
            "state INTEGER,"
            "subscription_identifier INT"
            # "state INTEGER,"
            # "FOREIGN KEY (client_id) REFERENCES clients(client_id) "
            # "ON DELETE CASCADE,"
            # "FOREIGN KEY (store_id) REFERENCES msg_store(store_id) "
            # "ON DELETE CASCADE"
            ");"
        )

    def __create_base_msgs_table(self):
        self.__cursor.execute(
            "CREATE TABLE IF NOT EXISTS base_msgs "
            "("
            "store_id INT64 PRIMARY KEY,"
            "expiry_time INT64,"
            "topic STRING NOT NULL,"
            "payload BLOB,"
            "source_id STRING,"
            "source_username STRING,"
            "payloadlen INTEGER,"
            "source_mid INTEGER,"
            "source_port INTEGER,"
            "qos INTEGER,"
            "retain INTEGER,"
            "properties STRING"
            ");"
        )

    def __create_retains_table(self):
        self.__cursor.execute(
            "CREATE TABLE IF NOT EXISTS retains "
            "("
            "topic STRING PRIMARY KEY,"
            "store_id INT64"
            # "FOREIGN KEY (store_id) REFERENCES msg_store(store_id) "
            # "ON DELETE CASCADE"
            ");"
        )

    def __create_subscriptions_table(self):
        self.__cursor.execute(
            "CREATE TABLE IF NOT EXISTS subscriptions "
            "("
            "client_id TEXT NOT NULL,"
            "topic TEXT NOT NULL,"
            "subscription_options INTEGER,"
            "subscription_identifier INTEGER,"
            "PRIMARY KEY (client_id, topic)"
            ");",
        )

    def __create_version_info_table(self):
        self.__cursor.execute(
            "CREATE TABLE IF NOT EXISTS version_info "
            "("
            "component TEXT NOT NULL,"
            "major INTEGER NOT NULL,"
            "minor INTEGER NOT NULL,"
            "patch INTEGER NOT NULL"
            ");"
        )

    def __create_tables(self):
        self.__create_clients_table()
        self.__create_client_msgs_table()
        self.__create_base_msgs_table()
        self.__create_retains_table()
        self.__create_subscriptions_table()
        self.__create_version_info_table()

    def __create_indices(self):
        self.__cursor.execute(
            "CREATE INDEX IF NOT EXISTS client_msgs_client_id ON client_msgs(client_id);"
        )
        self.__cursor.execute("DROP INDEX IF EXISTS client_msgs_store_id;")
        self.__cursor.execute(
            "CREATE INDEX IF NOT EXISTS client_msgs_store_id ON client_msgs(store_id,client_id);"
        )
        self.__cursor.execute(
            "CREATE INDEX IF NOT EXISTS retains_storeid ON retains(store_id);"
        )

    def __add_clients(self, clients: list[dict]):
        self.__cursor.executemany(
            "INSERT OR REPLACE INTO clients "
            "(client_id, username, connection_time, will_delay_time, session_expiry_time, "
            "listener_port, max_packet_size, max_qos, retain_available, "
            "session_expiry_interval, will_delay_interval) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    client["clientid"],
                    client["username"],
                    0,  # connection_time
                    0,  # will_delay_time
                    client["session-expiry-time"],
                    client["listener-port"],
                    0,  # max_packet_size
                    2,  # max_qos
                    True,  # retain_available
                    client["session-expiry-interval"],
                    0,  # will_delay_interval
                )
                for client in clients
            ],
        )

    def __add_client_msgs(self, client_msgs: list[dict]):
        for cmsg_counter, client_msg in enumerate(client_msgs, start=1):
            self.__cursor.execute(
                "INSERT INTO client_msgs "
                "(client_id,cmsg_id,store_id,dup,direction,mid,qos,"
                "retain,state,subscription_identifier) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    client_msg["clientid"],
                    cmsg_counter,  # cmsg_id
                    client_msg["storeid"],
                    0,  # dup
                    client_msg["direction"],
                    client_msg["mid"],
                    client_msg["qos"],
                    False,  # retain
                    client_msg["state"],
                    client_msg["subscription-identifier"],
                ),
            )

    def __add_base_msgs(self, base_msgs: list[dict]):
        for base_msg in base_msgs:
            self.__store_id_topic_map.update({base_msg["storeid"]: base_msg["topic"]})

            payload = base64.b64decode(base_msg["payload"]) if "payload" in base_msg else None

            self.__cursor.execute(
                "INSERT INTO base_msgs "
                "(store_id, expiry_time, topic, payload, source_id, source_username, "
                "payloadlen, source_mid, source_port, qos, retain, properties) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    base_msg["storeid"],
                    base_msg["expiry-time"],
                    base_msg["topic"],
                    payload if "payload" in base_msg else None,
                    base_msg["clientid"] if "clientid" in base_msg else None,
                    base_msg["username"] if "username" in base_msg else None,
                    len(payload) if "username" in base_msg else 0,
                    base_msg["source-mid"],
                    base_msg["source-port"],
                    base_msg["qos"],
                    base_msg["retain"],
                    base_msg["properties"] if "properties" in base_msg else None,
                ),
            )

    def __add_subscriptions(self, subscriptions: list[dict]):
        self.__cursor.executemany(
            "INSERT OR REPLACE INTO subscriptions "
            "(client_id, topic, subscription_options, subscription_identifier) "
            "VALUES (?,?,?,?)",
            [
                (
                    subscription["clientid"],
                    subscription["topic"],
                    subscription["options"],
                    subscription["identifier"],
                )
                for subscription in subscriptions
            ],
        )

    def __add_retained_messages(self, retained_messages: list[dict]):
        self.__cursor.executemany(
            "INSERT OR REPLACE INTO retains (topic, store_id) VALUES(?,?)",
            [
                (
                    self.__store_id_topic_map[retained_message["storeid"]],
                    retained_message["storeid"],
                )
                for retained_message in retained_messages
            ],
        )

    def migrate_to_persist_sqlite(
        self, snapshot_persistence: SnapshotPersistence
    ) -> Self:
        try:
            # self.__add_base_msgs must be executed before self.__add_retained_messages gets invoked
            self.__add_base_msgs(snapshot_persistence.base_messages)
            self.__add_retained_messages(snapshot_persistence.retained_messages)
            self.__add_subscriptions(snapshot_persistence.subscriptions)
            self.__add_clients(snapshot_persistence.clients)
            self.__add_client_msgs(snapshot_persistence.client_messages)
        except (sqlite3.Error, TypeError) as err:
            print(f"Error during SQLite3 DB creation. Reason: {str(err)}")
            self.__on_error()


# Migration


def find_mosquitto_db_dump() -> str:
    mosquitto_db_dump = shutil.which("mosquitto_db_dump")
    if mosquitto_db_dump is None:
        raise RuntimeError(
            'Could not find mosquitto_db_dump. Provide the path via the "--dump-tool" argument '
            "or make sure the executable is contained in your system's path."
        )
    return mosquitto_db_dump


def dump_mosquitto_db_to_json(
    mosquitto_db_dump: str, persistence_db_path: Path
) -> str:
    return subprocess.check_output(
        [
            mosquitto_db_dump,
            "--json",
            str(persistence_db_path),
        ]
    ).decode(encoding="utf-8")


def migrate_mosquitto_conf(mosquitto_conf: str, persist_sqlite_lib_path: Path) -> str:
    migrated_mosquitto_conf: list[str] = []
    for line in mosquitto_conf.splitlines():
        if line.startswith("persistence true"):
            migrated_mosquitto_conf.append(f"plugin {str(persist_sqlite_lib_path)}")
            continue

        migrated_mosquitto_conf.append(line)
    return "\n".join(migrated_mosquitto_conf)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--persistence-db", required=True, type=str, help="Path to mosquitto.db file"
    )
    parser.add_argument(
        "--conf", required=False, type=str, help="Path to mosquitto.conf file"
    )
    parser.add_argument(
        "--persist-sqlite-lib",
        required=False,
        type=str,
        help="Path to mosquitto_persist_sqlite.so/.dll",
    )
    parser.add_argument(
        "--dump-tool",
        required=False,
        type=str,
        help="Path to mosquitto_db_dump executable",
    )  # support local builds

    args = parser.parse_args()
    persistence_db_path = Path(args.persistence_db)
    mosquitto_db_dump = (
        args.dump_tool if args.dump_tool else find_mosquitto_db_dump()
    )

    if args.conf is not None:
        if args.persist_sqlite_lib is None:
            print(
                "Error: Cannot migrate mosquitto.conf file. Reason: --persist-sqlite-lib argument is missing"
            )
            sys.exit(1)

        # Migrate mosquitto.conf
        mosquitto_conf_path = Path(args.conf)
        mosquitto_conf = mosquitto_conf_path.read_text(encoding="utf-8")
        migrated_mosquitto_conf = migrate_mosquitto_conf(
            mosquitto_conf, Path(args.persist_sqlite_lib)
        )

        # Backup old mosquitto.conf and afterwards write migrated mosquitto.conf file
        mosquitto_conf_path.with_suffix(".conf.old.persistence").write_text(
            mosquitto_conf, encoding="utf-8"
        )
        mosquitto_conf_path.write_text(migrated_mosquitto_conf, encoding="utf-8")

    # Dump Snapshot persistence and parse JSON
    snapshot_persistence = SnapshotPersistence(
        dump_mosquitto_db_to_json(mosquitto_db_dump, persistence_db_path)
    )

    # Migrate Snapshot persistence and write SQLite3 file
    SQLite3Persistence().migrate_to_persist_sqlite(snapshot_persistence)


if __name__ == "__main__":
    main()
