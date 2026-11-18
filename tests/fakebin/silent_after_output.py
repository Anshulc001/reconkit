"""Prints three lines, then stays silent: the inactivity clock's fixture."""

import time

for index in range(3):
    print(f"url {index}", flush=True)
time.sleep(30)
