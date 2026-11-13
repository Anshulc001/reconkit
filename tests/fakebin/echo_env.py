import os

for key in sorted(os.environ):
    print(f"{key}={os.environ[key]}")
