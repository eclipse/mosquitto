#!/bin/bash -eu
#
# Copyright (c) 2023 Cedalo GmbH
#
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Eclipse Public License 2.0
# and Eclipse Distribution License v1.0 which accompany this distribution.
#
# The Eclipse Public License is available at
#   https://www.eclipse.org/legal/epl-2.0/
# and the Eclipse Distribution License is available at
#   http://www.eclipse.org/org/documents/edl-v10.php.
#
# SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
#
# Contributors:
#    Roger Light - initial implementation and documentation.


# Note that sqlite3 is required as a build dep of a plugin which is not
# currently part of fuzz testing. Once it is part of fuzz testing, sqlite will
# need to be built statically.
apt-get update && apt-get install -y libtool-bin make libsqlite3-dev
git clone https://github.com/DaveGamble/cJSON ${SRC}/cJSON
