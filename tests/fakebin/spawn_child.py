import subprocess
import sys
import time

pid_file = sys.argv[1]
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
with open(pid_file, "w", encoding="utf-8") as handle:
    handle.write(str(child.pid))
time.sleep(60)
