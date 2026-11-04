"""Run with:  python -m netmon [-c config.yaml] [--demo]"""
import argparse
import logging

import uvicorn

from .app import create_app
from .config import Config, load_config


def main():
    ap = argparse.ArgumentParser(prog="netmon", description="Live network monitor for Cisco switches")
    ap.add_argument("-c", "--config", default="config.yaml", help="path to config.yaml")
    ap.add_argument("--demo", action="store_true", help="run with simulated switches (no config needed)")
    ap.add_argument("--port", type=int, help="override web port")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")

    if args.demo:
        cfg = Config(demo=True, db_path="netmon-demo.db", poll_interval=15)
        try:
            real = load_config(args.config)
            cfg.alerts = real.alerts          # let the demo test your email/Teams settings
            cfg.dashboard_url = real.dashboard_url
        except FileNotFoundError:
            pass
    else:
        cfg = load_config(args.config)
    if args.port:
        cfg.web_port = args.port

    uvicorn.run(create_app(cfg), host=cfg.web_host, port=cfg.web_port, log_level="warning")


if __name__ == "__main__":
    main()
