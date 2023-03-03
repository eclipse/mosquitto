import logging
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s %(asctime)s.%(msecs)03d %(module)s: %(message)s",
    datefmt="%H:%M:%S",
)

current_source_dir = Path(__file__).resolve().parent
test_dir = current_source_dir.parents[1]
if test_dir not in sys.path:
    sys.path.insert(0, str(test_dir))

ssl_dir = test_dir / "ssl"

import mosq_test
import subprocess
import os
