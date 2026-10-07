<!--
.. title: Sqlite Persistence
.. slug: sqlite
.. date: 2026-01-30 09:00:00 UTC
.. tags:
.. category:
.. link:
.. description:
.. type: text
-->

## Introduction

Available since version 2.1.

This plugin provides a replacement for the traditional mosquitto persistence
normally enabled with `persistence true`.

This plugin should be preferred when you are interested in persistence, because
it saves changes to disk as they are made, where as the traditional persistence
only takes periodic snapshots.

Note that it is not possible to run both the traditional persistence and the
sqlite persistence plugin at the same time.


## Usage

The plugin requires minimal configuration.

The database is stored at the location specified by the `persistence_location`
option and is named `mosquitto.sqlite3. As an alternative, the file can be
specified directly using the `plugin_opt_db_file` option.

The `plugin_opt_sync` option can be set to `extra`, `full`, `normal`, or `off`,
with a default of `normal`. This option controls how hard sqlite works to
ensure data is on the disk before continuing. This is better described by
[sqlite themselves](https://www.sqlite.org/pragma.html#pragma_synchronous).

The `plugin_opt_page_size` option sets the database page size, as described
[here](https://www.sqlite.org/pragma.html#pragma_page_size).

The `plugin_opt_flush_period` option is a positive integer number of seconds,
defaulting to 5, that the plugin will batch database updates over in order to
improve performance.

# Config

Windows:
```
persistence_location <path to save mosquitto.sqlite3>
global_plugin C:\Program Files\Mosquitto\mosquitto_persist_sqlite.dll
```

Other:
```
persistence_location <path to save mosquitto.sqlite3>
global_plugin /path/to/mosquitto_persist_sqlite.so
```

# Migration

A [script](https://raw.githubusercontent.com/eclipse-mosquitto/mosquitto/refs/heads/master/plugins/persist-sqlite/migrate_to_persist_sqlite.py)
is available to help migrate from the traditional persistence.
