#!/usr/bin/env python3

import os
import shutil
import subprocess
import time
from pathlib import Path

def run_merge(processes, d1, d2, output_dir):
    cmd = ["gcov-tool", "merge", "-o", output_dir, d1, d2]
    proc = subprocess.Popen(cmd)
    proc.output_dir = output_dir
    processes.append(proc)


final_output_dir = "cov-merged"
os.mkdir(final_output_dir)

dirs = []
with os.scandir('.') as scan:
    for d in scan:
        if "coverage." in d.name and d.is_dir():
            dirs.append(d.name)

max_process_count = 20
process_count = 0
processes = []
merge_index = 0

dirs_to_remove = []

while len(dirs) > 0 or len(processes) > 0:
    for p in processes:
        p.poll()
        if p.returncode is not None:
            processes.remove(p)
            if p.output_dir != final_output_dir:
                dirs.append(p.output_dir)

    if len(dirs) == 1 and len(processes) == 0:
        d1 = dirs.pop()
        d2 = final_output_dir
        output_dir = final_output_dir

        dirs_to_remove.append(d1)

        run_merge(processes, d1, d2, output_dir)
    elif len(dirs) > 1 and len(processes) < max_process_count:
        d1 = dirs.pop()
        d2 = dirs.pop()

        output_dir = f"tmp{merge_index}"
        merge_index += 1

        dirs_to_remove.append(d1)
        dirs_to_remove.append(d2)

        run_merge(processes, d1, d2, output_dir)
    else:
        time.sleep(0.1)

files = list(Path(final_output_dir).iterdir())
for f in files:
    shutil.move(f, f.name.replace("#", "/"))

dirs_to_remove.sort()
for d in dirs_to_remove:
    print(d)
    shutil.rmtree(d)
os.rmdir(final_output_dir)
