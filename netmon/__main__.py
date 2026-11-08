"""Run NetMon.

    python -m netmon --demo                         simulated building, http://localhost:8080
    python -m netmon -c config.yaml                 real monitoring
    python -m netmon -c config.yaml user add mina --role admin
    python -m netmon -c config.yaml user list | passwd <name> | role <name> <admin|viewer> | del <name>
"""
import argparse
import getpass
import logging

from .config import AuthCfg, Config, load_config


def user_command(args):
    from .auth import Auth, AuthError
    from .db import Database
    if args.demo:
        raise SystemExit("user commands work on a real config: python -m netmon -c config.yaml user ...")
    cfg = load_config(args.config)
    auth = Auth(Database(cfg.db_path), cfg.auth)
    try:
        if args.action == "list":
            rows = auth.users()
            if not rows:
                print("no users yet")
            for u in rows:
                print(f"{u['username']:20} {u['role']}")
            return
        if not args.name:
            raise SystemExit("give a user name")
        if args.action in ("add", "passwd"):
            pw = getpass.getpass(f"Password for {args.name}: ")
            if pw != getpass.getpass("Repeat password: "):
                raise SystemExit("passwords do not match")
            if args.action == "add":
                auth.add_user(args.name, pw, args.role)
                print(f"user {args.name} created ({args.role})")
            else:
                auth.set_password(args.name, pw)
                print(f"password changed for {args.name}; their sessions were logged out")
        elif args.action == "role":
            auth.set_role(args.name, args.role_value or args.role)
            print(f"{args.name} is now {args.role_value or args.role}")
        elif args.action == "del":
            auth.delete_user(args.name)
            print(f"user {args.name} deleted")
    except AuthError as e:
        raise SystemExit(f"error: {e}")


def main():
    ap = argparse.ArgumentParser(prog="netmon", description="Live network monitor for Cisco switches")
    ap.add_argument("-c", "--config", default="config.yaml", help="path to config.yaml")
    ap.add_argument("--demo", action="store_true", help="run with simulated switches (no config needed)")
    ap.add_argument("--port", type=int, help="override web port")
    sub = ap.add_subparsers(dest="cmd")
    u = sub.add_parser("user", help="manage dashboard users")
    u.add_argument("action", choices=["add", "list", "passwd", "role", "del"])
    u.add_argument("name", nargs="?")
    u.add_argument("role_value", nargs="?", choices=["admin", "viewer"])
    u.add_argument("--role", choices=["admin", "viewer"], default="viewer")
    args = ap.parse_args()

    if args.cmd == "user":
        return user_command(args)

    import uvicorn

    from .app import create_app
    from .credentials import SecretsError, apply_secrets

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")

    if args.demo:
        # simulated switches only: no credentials, no network devices, no alerts sent.
        # Only reachable from this computer, so no login is needed.
        cfg = Config(demo=True, db_path="netmon-demo.db", poll_interval=15, web_host="127.0.0.1",
                     auth=AuthCfg(enabled=False))
    else:
        cfg = load_config(args.config)
        try:
            apply_secrets(cfg)
        except SecretsError as e:
            raise SystemExit(f"NetMon not started: {e}")
    if args.port:
        cfg.web_port = args.port

    uvicorn.run(create_app(cfg), host=cfg.web_host, port=cfg.web_port, log_level="warning")


if __name__ == "__main__":
    main()
