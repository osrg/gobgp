#!/usr/bin/env python3
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


INITIAL_TESTS = [
    ("rs", "route_server_test.py", "gobgp"),
    ("v6", "route_server_ipv4_v6_test.py", "gobgp"),
    ("bgp", "bgp_router_test.py", "gobgp"),
    ("ibgp", "ibgp_router_test.py", "gobgp"),
    ("evpn", "evpn_test.py", "gobgp"),
    ("flow", "flow_spec_test.py", "gobgp"),
    ("rr", "route_reflector_test.py", "gobgp"),
    ("zebra", "bgp_zebra_test.py", "gobgp"),
    ("gpol", "global_policy_test.py", "gobgp"),
    ("as2", "route_server_as2_test.py", "gobgp"),
    ("gr", "graceful_restart_test.py", "gobgp"),
    ("un", "bgp_unnumbered_test.py", "gobgp"),
    ("md5", "tcp_md5_test.py", "gobgp"),
    ("rs2", "route_server_test2.py", "gobgp"),
    ("softreset", "route_server_softreset_test.py", "gobgp"),
    ("llgr", "long_lived_graceful_restart_test.py", "gobgp"),
    ("vrf", "vrf_neighbor_test.py", "gobgp"),
    ("vrf2", "vrf_neighbor_test2.py", "gobgp"),
    ("rtc", "rtc_test.py", "gobgp"),
    ("aspath", "aspath_test.py", "gobgp"),
    ("addpath", "addpath_test.py", "gobgp"),
    ("malh", "bgp_malformed_msg_handling_test.py", "gobgp"),
    ("confed", "bgp_confederation_test.py", "gobgp"),
    ("zebra-nht", "bgp_zebra_nht_test.py", "gobgp-oq"),
    ("zapi3", "zapi_v3_test.py", "gobgp-oq"),
    ("zapi3mp", "zapi_v3_multipath_test.py", "gobgp-oq"),
    ("mup", "mup_test.py", "gobgp"),
]


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Run all GoBGP scenario tests.")
    parser.add_argument(
        "--timeout-scale",
        default=os.environ.get("GOBGP_TEST_TIMEOUT_SCALE", "1.0"),
        metavar="SCALE",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="hide pytest output but keep run/pass/fail progress",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="stop after the first failing pytest invocation",
    )
    return parser.parse_args(argv)


def clean_pycache(test_dir):
    for root in (test_dir, test_dir.parent / "lib"):
        if not root.exists():
            continue
        for path in root.rglob("__pycache__"):
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=True)


class PytestRun:
    def __init__(self, prefix, label, process, output_file=None, progress=False):
        self.prefix = prefix
        self.label = label
        self.process = process
        self.output_file = output_file
        self.output_path = Path(output_file.name) if output_file is not None else None
        self.progress = progress

    def finish(self):
        returncode = self.process.wait()
        if self.output_file is not None:
            self.output_file.close()
            self.output_file = None
        return returncode

    def terminate(self):
        if self.process.poll() is None:
            self.process.terminate()

    def dump_output(self):
        if self.output_path is None or not self.output_path.exists():
            return
        print(f"\n[{self.prefix}] pytest output:")
        with self.output_path.open("r", errors="replace") as output:
            shutil.copyfileobj(output, sys.stdout)

    def cleanup(self):
        if self.output_path is not None:
            try:
                self.output_path.unlink()
            except FileNotFoundError:
                pass


class Runner:
    def __init__(self, test_dir, timeout_scale, env, quiet=False):
        self.test_dir = test_dir
        self.timeout_scale = timeout_scale
        self.env = env
        self.quiet = quiet

    def pytest_command(self, prefix, args):
        cache_dir = Path("/tmp/gobgp-pytest-cache") / prefix
        base_temp = Path("/tmp/gobgp-pytest-temp") / prefix
        shutil.rmtree(cache_dir, ignore_errors=True)
        shutil.rmtree(base_temp, ignore_errors=True)
        cache_dir.mkdir(parents=True, exist_ok=True)
        base_temp.mkdir(parents=True, exist_ok=True)

        return [
            sys.executable,
            "-m",
            "pytest",
            "--import-mode=importlib",
            "-o",
            f"cache_dir={cache_dir}",
            f"--basetemp={base_temp}",
            "--timeout-scale",
            self.timeout_scale,
            *[str(arg) for arg in args],
        ]

    def pytest_label(self, prefix, args):
        test_file = Path(args[0]).name if args else "pytest"
        label = f"{prefix} {test_file}"
        if "--test-index" in args:
            index = args[args.index("--test-index") + 1]
            label = f"{label} index={index}"
        return label

    def start_pytest(self, prefix, *args):
        label = self.pytest_label(prefix, args)
        if not self.quiet:
            return PytestRun(
                prefix,
                label,
                subprocess.Popen(
                    self.pytest_command(prefix, args),
                    env=self.env,
                ),
            )

        print(f"[run] {label}", flush=True)

        output_file = tempfile.NamedTemporaryFile(
            prefix=f"gobgp-scenario-{prefix}-",
            suffix=".log",
            mode="w",
            delete=False,
        )
        return PytestRun(
            prefix,
            label,
            subprocess.Popen(
                self.pytest_command(prefix, args),
                env=self.env,
                stdout=output_file,
                stderr=subprocess.STDOUT,
                text=True,
            ),
            output_file=output_file,
            progress=True,
        )

    def run_pytest_capture(self, prefix, *args):
        return subprocess.run(
            self.pytest_command(prefix, args),
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )


def wait_pytest(process):
    try:
        returncode = process.finish()
    except KeyboardInterrupt:
        process.terminate()
        raise

    if process.progress:
        state = "pass" if returncode == 0 else "fail"
        print(f"[{state}] {process.label}", flush=True)

    failures = []
    status = 0
    if returncode != 0:
        failures.append(process.label)
        process.dump_output()
        status = returncode
    process.cleanup()
    return status, failures


def parse_index_count(output):
    count = None
    for line in output.splitlines():
        if "invalid" in line:
            fields = line.split()
            if fields:
                count = fields[-1]
    if count is None:
        raise RuntimeError("could not find scenario count in pytest output")
    return int(count)


def get_index_count(runner, prefix, test_file):
    result = runner.run_pytest_capture(
        prefix,
        runner.test_dir / test_file,
        "--test-index",
        "-1",
        "-s",
    )
    if result.returncode != 0:
        print(result.stdout, end="")
        raise subprocess.CalledProcessError(result.returncode, result.args)
    return parse_index_count(result.stdout)


def run_initial_tests(
    runner,
    gobgp_image,
    gobgp_oq_image,
    fail_fast=False,
):
    status = 0
    failures = []
    for prefix, test_file, image_kind in INITIAL_TESTS:
        image = gobgp_oq_image if image_kind == "gobgp-oq" else gobgp_image
        process = runner.start_pytest(
            prefix,
            runner.test_dir / test_file,
            "--gobgp-image",
            image,
            "--test-prefix",
            prefix,
            "-s",
            "-x",
        )
        run_status, run_failures = wait_pytest(process)
        failures.extend(run_failures)
        if run_status != 0 and status == 0:
            status = run_status
        if run_status != 0 and fail_fast:
            return status, failures
    return status, failures


def run_indexed_tests(
    runner,
    test_file,
    count_prefix,
    test_prefix,
    gobgp_image,
    fail_fast=False,
):
    count = get_index_count(runner, f"{count_prefix}-count", test_file)
    status = 0
    failures = []
    for index in range(1, count + 1):
        prefix = f"{test_prefix}{index}"
        run_status, run_failures = wait_pytest(
            runner.start_pytest(
                prefix,
                runner.test_dir / test_file,
                "--gobgp-image",
                gobgp_image,
                "--test-prefix",
                prefix,
                "--test-index",
                str(index),
                "-s",
                "-x",
                "--gobgp-log-level",
                "debug",
            )
        )
        failures.extend(run_failures)
        if run_status != 0 and status == 0:
            status = run_status
        if run_status != 0 and fail_fast:
            return status, failures
        if index != count:
            time.sleep(3)
    return status, failures


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])

    cwd = Path.cwd().resolve()
    gobgp_image = os.environ.get("GOBGP_IMAGE", "gobgp")
    gobgp_oq_image = os.environ.get("GOBGP_OQ_IMAGE", "gobgp-oq")
    test_dir = cwd / "test" / "scenario_test"

    env = os.environ.copy()
    env["PYTHONPATH"] = str(cwd / "test")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["GOBGP_TEST_TIMEOUT_SCALE"] = args.timeout_scale

    clean_pycache(test_dir)
    runner = Runner(test_dir, args.timeout_scale, env, quiet=args.quiet)
    failures = []
    status = 0

    if args.quiet:
        mode = "fail-fast" if args.fail_fast else "keep-going"
        print(f"[mode] sequential {mode}", flush=True)

    run_status, run_failures = run_initial_tests(
        runner,
        gobgp_image,
        gobgp_oq_image,
        fail_fast=args.fail_fast,
    )
    failures.extend(run_failures)
    if run_status != 0 and status == 0:
        status = run_status
    if run_status != 0 and args.fail_fast:
        print("scenario test run stopped (--fail-fast) after initial scenario failure", file=sys.stderr)
        return status

    run_status, run_failures = run_indexed_tests(
        runner,
        "route_server_malformed_test.py",
        "mal",
        "mal",
        gobgp_image,
        fail_fast=args.fail_fast,
    )
    failures.extend(run_failures)
    if run_status != 0 and status == 0:
        status = run_status
    if run_status != 0 and args.fail_fast:
        print("scenario test run stopped (--fail-fast) after route_server_malformed failure", file=sys.stderr)
        return status

    run_status, run_failures = run_indexed_tests(
        runner,
        "route_server_policy_test.py",
        "pol",
        "p",
        gobgp_image,
        fail_fast=args.fail_fast,
    )
    failures.extend(run_failures)
    if run_status != 0 and status == 0:
        status = run_status
    if run_status != 0 and args.fail_fast:
        print("scenario test run stopped (--fail-fast) after route_server_policy failure", file=sys.stderr)
        return status

    run_status, run_failures = run_indexed_tests(
        runner,
        "route_server_policy_grpc_test.py",
        "pg",
        "pg",
        gobgp_image,
        fail_fast=args.fail_fast,
    )
    failures.extend(run_failures)
    if run_status != 0 and status == 0:
        status = run_status
    if run_status != 0 and args.fail_fast:
        print("scenario test run stopped (--fail-fast) after route_server_policy_grpc failure", file=sys.stderr)
        return status

    if status != 0:
        print("scenario test run completed with failures:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return status

    print("all tests passed successfully")
    return 0


if __name__ == "__main__":
    sys.exit(main())
