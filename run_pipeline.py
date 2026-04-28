import subprocess
import sys
import os
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

SCRIPTS = [
    BASE_DIR / "dbapp" / "api_json" / "modified_ingest_api.py",

    # Automotive Flow
    BASE_DIR / "dbapp" / "automotive_ai" / "usinggrok.py",
    BASE_DIR / "dbapp" / "automotive_ai" / "aigeneration.py",

    # IoT & Embedded Flow
    BASE_DIR / "dbapp" / "automotive_ai" / "usinggrok2.py",
    BASE_DIR / "dbapp" / "automotive_ai" / "aigeneration2.py",
]

def run_script(script_path):
    print(f"\n==== [{datetime.now()}] Running {script_path.name} ====")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(BASE_DIR)
    env["PYTHONIOENCODING"] = "utf-8"
    result = subprocess.run([sys.executable, str(script_path)], env=env)
    if result.returncode != 0:
        print(f"{script_path.name} failed with exit code {result.returncode}")
        return False
    print(f"{script_path.name} completed successfully")
    return True

def main():
    print(f"Pipeline started at {datetime.now()}")
    for script in SCRIPTS:
        if not run_script(script):
            break
    print(f"Pipeline finished at {datetime.now()}\n")

if __name__ == "__main__":
    main()
