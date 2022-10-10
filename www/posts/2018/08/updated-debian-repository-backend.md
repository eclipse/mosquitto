<!--
.. title: Updated Debian Repository Backend
.. slug: updated-debian-repository-backend
.. date: 2018-08-08 23:00:43 UTC+01:00
.. tags: Packaging
.. category:
.. link:
.. description:
.. type: text
-->

The backend software for administering the Debian repository at
https://repo.mosquitto.org/ has been migrated from `reprepro` to `aptly`. This
has the benefit of allowing multiple versions of a package to remain in the
repository.

For mosquitto, this now means that old versions of the Debian packages will
remain available even after newer versions are published, and so you can depend
on a particular version. The recommendation is always to use the latest version
of course.

This change should be transparent to all current users, but there is the
possibility that something is different between the two repository tools. If
you do find a problem, please let us know.

The repository now has builds for versions 1.4.15 and 1.5.
