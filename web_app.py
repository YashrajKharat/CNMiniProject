#!/usr/bin/env python3
"""The web app: login, add network, live dashboard, reports.

    venv/bin/python web_app.py                      (no sudo)
    venv/bin/python web_app.py --report-every-min 60

Then open http://127.0.0.1:5000 . The monitor (run_monitor.py) runs separately
with sudo; the two talk through files in data/.
"""
import argparse

from config import DATA_DIR
from webapp import create_app


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1",
                    help="address to listen on (default: this computer only)")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--data-dir", default=DATA_DIR)
    ap.add_argument("--report-every-min", type=int, default=0,
                    help="create a report this often (0 = only when you ask)")
    args = ap.parse_args()
    app = create_app(args.data_dir, report_every_min=args.report_every_min)
    if app.scheduler:
        app.scheduler.start()
        print(f"A report will be created every {args.report_every_min} minutes.")
    print(f"Open http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()
