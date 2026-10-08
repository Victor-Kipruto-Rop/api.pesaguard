"""Select deployment configuration without sourcing .env as executable shell code."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys

from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parent.parent


def server_name(env_file: Path) -> str:
    values = dotenv_values(env_file, interpolate=False)
    name = os.environ.get("API_SERVER_NAME", values.get("API_SERVER_NAME", ""))
    # Accept one DNS hostname only, not nginx directives, wildcards or URLs.
    if not name or len(name) > 253 or not all(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
        for label in name.split(".")
    ):
        raise ValueError("API_SERVER_NAME must be a single valid DNS hostname")
    return name


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, default=ROOT / ".env")
    commands = parser.add_subparsers(dest="command", required=True)
    compose = commands.add_parser("compose", help="Forward arguments to Docker Compose")
    compose.add_argument("args", nargs=argparse.REMAINDER)
    commands.add_parser("render-nginx", help="Print the rendered host nginx configuration")
    args = parser.parse_args(argv)
    env_file = args.env_file.resolve()
    if not env_file.is_file():
        print("Deployment environment file is missing", file=sys.stderr)
        return 2
    try:
        if args.command == "render-nginx":
            template = ROOT / "infra/nginx/pesaguard-api.conf"
            sys.stdout.write(template.read_text(encoding="utf-8").replace(
                "${API_SERVER_NAME}", server_name(env_file)
            ))
            return 0
        forwarded = args.args
        if forwarded[:1] == ["--"]:
            forwarded = forwarded[1:]
        if any(arg == "--env-file" or arg.startswith("--env-file=") for arg in forwarded):
            raise ValueError("Select --env-file before the compose subcommand")
        env = os.environ.copy()
        env["PESAGUARD_COMPOSE_ENV_FILE"] = str(env_file)
        return subprocess.run(
            ["docker", "compose", "--env-file", str(env_file), *forwarded],
            cwd=ROOT, env=env, check=False,
        ).returncode
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except OSError:
        print("Configuration command could not be executed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
