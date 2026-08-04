#!/usr/bin/env python3
import argparse
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path


TEST_LABEL = os.environ.get("GOBGP_TEST_LABEL", "gobgp-test")
TEST_BASE_DIR = os.environ.get("GOBGP_TEST_BASE_DIR", "/tmp/gobgp")
PYTEST_CACHE_DIR = os.environ.get("GOBGP_PYTEST_CACHE_DIR", "/tmp/gobgp-pytest-cache")
PYTEST_TEMP_DIR = os.environ.get("GOBGP_PYTEST_TEMP_DIR", "/tmp/gobgp-pytest-temp")
DIND_DATA_VOLUME = os.environ.get("GOBGP_BUILDER_DOCKER_DATA", "gobgp_builder_docker_data")


def run(command, dry_run=False, **kwargs):
    if dry_run:
        print("[dry-run] " + shlex.join(command))
        return subprocess.CompletedProcess(command, 0)
    return subprocess.run(command, check=True, **kwargs)


def run_output(command):
    return subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    ).stdout


def docker_available():
    if shutil.which("docker") is None:
        print("docker: not found, skipping Docker cleanup")
        return False

    info = subprocess.run(
        ["docker", "info"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if info.returncode != 0:
        print("docker: daemon is unavailable, skipping Docker cleanup")
        return False
    return True


def remove_docker_leftovers(dry_run=False, remove_dind_volume=False):
    if not docker_available():
        return

    containers = run_output(
        ["docker", "ps", "-aq", "-f", f"label={TEST_LABEL}"]
    ).split()
    if containers:
        print(f"Removing containers with label={TEST_LABEL}: {len(containers)}")
        run(["docker", "rm", "-f", *containers], dry_run=dry_run)
    else:
        print(f"Removing containers with label={TEST_LABEL}: none")

    networks = run_output(
        ["docker", "network", "ls", "-q", "-f", f"label={TEST_LABEL}"]
    ).split()
    if networks:
        print(f"Removing networks with label={TEST_LABEL}: {len(networks)}")
        run(["docker", "network", "rm", *networks], dry_run=dry_run)
    else:
        print(f"Removing networks with label={TEST_LABEL}: none")

    if remove_dind_volume:
        volume = subprocess.run(
            ["docker", "volume", "inspect", DIND_DATA_VOLUME],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if volume.returncode == 0:
            print(f"Removing DinD data volume: {DIND_DATA_VOLUME}")
            run(["docker", "volume", "rm", "-f", DIND_DATA_VOLUME], dry_run=dry_run)
        else:
            print("Removing DinD data volume: none")


def remove_path(path):
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def safe_remove_path(path, dry_run=False):
    if not path or path == "/":
        print(f"Refusing to remove unsafe path: {path or '<empty>'}", file=sys.stderr)
        return 1

    target = Path(path)
    if not target.exists() and not target.is_symlink():
        print(f"Removing {path}: none")
        return 0

    if shutil.which("mountpoint") is not None:
        mountpoint = subprocess.run(
            ["mountpoint", "-q", path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if mountpoint.returncode == 0:
            print(f"Clearing contents of mounted {path}")
            if dry_run:
                command = [
                    "find",
                    path,
                    "-mindepth",
                    "1",
                    "-maxdepth",
                    "1",
                    "-exec",
                    "rm",
                    "-rf",
                    "--",
                    "{}",
                    "+",
                ]
                print("[dry-run] " + shlex.join(command))
                return 0
            for child in target.iterdir():
                remove_path(child)
            return 0

    print(f"Removing {path}")
    if dry_run:
        print("[dry-run] " + shlex.join(["rm", "-rf", path]))
        return 0
    remove_path(target)
    return 0


def remove_tmp_leftovers(dry_run=False, keep_tmp=False):
    if keep_tmp:
        print("Keeping temporary directories")
        return 0

    status = 0
    for path in (TEST_BASE_DIR, PYTEST_CACHE_DIR, PYTEST_TEMP_DIR):
        status = max(status, safe_remove_path(path, dry_run=dry_run))
    return status


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Clean scenario test leftovers from Docker and temporary directories."
    )
    parser.add_argument("--dry-run", action="store_true", help="print what would be removed")
    parser.add_argument(
        "--keep-tmp",
        action="store_true",
        help="keep temporary scenario directories",
    )
    parser.add_argument(
        "--remove-dind-volume",
        action="store_true",
        help=f"remove {DIND_DATA_VOLUME}; this drops DinD image cache",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    remove_docker_leftovers(
        dry_run=args.dry_run,
        remove_dind_volume=args.remove_dind_volume,
    )
    return remove_tmp_leftovers(dry_run=args.dry_run, keep_tmp=args.keep_tmp)


if __name__ == "__main__":
    sys.exit(main())
