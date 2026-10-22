"""Web server and normal-traffic generators for the simulated network."""
import os
import subprocess

from config import CLIENTS, WEB_IP, WWW_DIR

# Runs inside a client host's namespace: random HTTP requests, small pages
# mostly, an occasional bigger file, random pauses.
CLIENT_CODE = r"""
import random, sys, time, urllib.request
base = sys.argv[1]
while True:
    path = random.choice(["/", "/", "/", "/", "/", "/file.bin"])
    try:
        urllib.request.urlopen(base + path, timeout=3).read()
    except Exception:
        pass
    time.sleep(random.uniform(0.3, 2.0))
"""


def prepare_www():
    os.makedirs(WWW_DIR, exist_ok=True)
    index = os.path.join(WWW_DIR, "index.html")
    with open(index, "w") as f:
        f.write("<html><body><h1>ANE test web server</h1></body></html>")
    blob = os.path.join(WWW_DIR, "file.bin")
    if not os.path.exists(blob):
        with open(blob, "wb") as f:
            f.write(os.urandom(150_000))


def start_services(net):
    """Start the HTTP server on the 'web' host. Returns a list of Popens."""
    prepare_www()
    web = net.get("web")
    proc = web.popen(["python3", "-m", "http.server", "80",
                      "--directory", WWW_DIR],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return [proc]


def start_normal_traffic(net, clients=CLIENTS):
    """Start one background HTTP client on each client host."""
    procs = []
    for name in clients:
        host = net.get(name)
        procs.append(host.popen(
            ["python3", "-c", CLIENT_CODE, f"http://{WEB_IP}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    return procs


def stop_processes(procs):
    """Stop background processes. Must run before net.stop(), otherwise
    leftover processes keep the Mininet namespaces alive."""
    for p in procs:
        try:
            p.terminate()
        except Exception:
            pass
    for p in procs:
        try:
            p.wait(timeout=3)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
