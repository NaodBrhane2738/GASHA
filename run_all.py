import subprocess
import sys
import time
import os
import signal

def run():
    print("=" * 60)
    print("Starting GASHA Platform Full Stack...")
    print("=" * 60)
    
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 1. Core API
    print("[1/4] Starting GASHA Core API on http://0.0.0.0:4000...")
    api_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--app-dir", "apps/api", "--host", "0.0.0.0", "--port", "4000"],
        cwd=base_dir
    )
    
    # 2. Demo Target Storefront
    print("[2/4] Starting Nexus Storefront Target on http://0.0.0.0:3101...")
    store_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--app-dir", "apps/demo-target", "--host", "0.0.0.0", "--port", "3101"],
        cwd=base_dir
    )
    
    # 3. Attacker Console
    print("[3/4] Starting Attacker Console on http://0.0.0.0:3102...")
    attacker_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--app-dir", "apps/attacker-console", "--host", "0.0.0.0", "--port", "3102"],
        cwd=base_dir
    )
    
    # 4. Web Console
    print("[4/4] Starting GASHA Web Console on http://0.0.0.0:3100...")
    pnpm_cmd = "pnpm.cmd" if sys.platform == "win32" else "pnpm"
    web_proc = subprocess.Popen(
        [pnpm_cmd, "--filter", "@gasha/web", "dev"],
        cwd=base_dir
    )
    
    print("\n" + "=" * 60)
    print("All services are starting up!")
    print("Web Console:      http://localhost:3100")
    print("Demo Storefront:  http://localhost:3101")
    print("Attacker Console: http://localhost:3102")
    print("Core API Docs:    http://localhost:4000/docs")
    print("Credentials:      analyst01 / agis")
    print("Press Ctrl+C to stop all services.")
    print("=" * 60 + "\n")
    
    procs = [api_proc, store_proc, attacker_proc, web_proc]
    try:
        while True:
            time.sleep(1)
            for p in procs:
                if p.poll() is not None:
                    pass
    except KeyboardInterrupt:
        print("\nStopping all services...")
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        print("All services stopped.")

if __name__ == "__main__":
    run()
