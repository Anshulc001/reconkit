import os
import sys
import time

with open(sys.argv[1], "w", encoding="utf-8") as handle:
    handle.write(str(os.getpid()))
time.sleep(30)
