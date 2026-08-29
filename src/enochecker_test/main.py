import argparse
import logging
import os
import sys
from typing import Optional

import httpx
import pytest
from enochecker_core import CheckerInfoMessage

# Stress tests flood the checker with hundreds of concurrent tasks, and utf8
# flags exercise an encoding most services never see, so both are opt-in:
# naming any markexpr at all overrides this and can select them back in.
DEFAULT_MARK_EXPR = "not stress and not utf8"


def run_tests(
    host: str,
    port: int,
    service_address: str,
    mark_expr: str,
    multiplier: int,
    seed: int,
    exploit_timeout: Optional[int] = None,
    variant: Optional[int] = None,
    name_expr: Optional[str] = None,
):
    transport = httpx.HTTPTransport(retries=10)
    with httpx.Client(transport=transport) as client:
        r = client.get(f"http://{host}:{port}/service")
    if r.status_code != 200:
        raise Exception("Failed to get /service from checker")
    try:
        info = CheckerInfoMessage.model_validate_json(r.text)
    except ValueError as e:
        raise Exception(
            "Failed to parse /service from checker. Note that exploitVariants is now "
            "the list of flag variants targeted by each exploit, not their count."
        ) from e
    logging.info(
        "Testing service %s, flagVariants: %d, noiseVariants: %d, havocVariants: %d, exploitVariants: %s, testVariants: %d",
        info.service_name,
        info.flag_variants,
        info.noise_variants,
        info.havoc_variants,
        info.exploit_variants,
        info.test_variants,
    )

    # An out-of-range variant would otherwise parametrize every method with an
    # empty set, which pytest reports as "skipped" rather than as a bad option.
    max_variants = max(
        info.flag_variants,
        info.noise_variants,
        info.havoc_variants,
        len(info.exploit_variants),
        info.test_variants,
    )
    if variant is not None and not 0 <= variant < max_variants:
        raise Exception(
            f"Invalid variant {variant}, the checker declares at most "
            f"{max_variants} variants for any of its methods"
        )

    test_args = [
        f"--checker-address={host}",
        f"--checker-port={port}",
        f"--service-address={service_address}",
        f"--service-name={info.service_name}",
        f"--flag-variants={info.flag_variants}",
        f"--noise-variants={info.noise_variants}",
        f"--havoc-variants={info.havoc_variants}",
        "--exploit-variants=" + ",".join(str(v) for v in info.exploit_variants),
        f"--test-variants={info.test_variants}",
        f"--multiplier={multiplier}",
        f"--seed={seed}",
        "--durations=0",
        "-v",
        "-o",
        "asyncio_mode=auto",
    ]
    if exploit_timeout is not None:
        test_args.append(f"--exploit-timeout={exploit_timeout}")
    if variant is not None:
        test_args.append(f"--variant={variant}")
    test_args.append("-m")
    test_args.append(mark_expr or DEFAULT_MARK_EXPR)
    if name_expr:
        test_args.append("-k")
        test_args.append(name_expr)
    test_args.append(os.path.join(os.path.dirname(__file__), "tests.py"))

    sys.exit(pytest.main(test_args))


def main():
    parser = argparse.ArgumentParser(
        prog="enochecker_test",
        # don't reformat but use description and epilog verbatim
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Utility for testing checkers that implement the enochecker API",
        epilog="""Example Usage:

    $ enochecker_test -a localhost -p 5008 -A 172.20.0.1 putflag

Assuming that 172.20.0.1 is the ip address of the gateway of the network of the
service's docker container as obtained by e.g:

    $ docker network inspect service_default | jq ".[].IPAM.Config[].Gateway"

By default all tests run. Three independent filters narrow that down, and a
test must pass all of the ones given. markexpr (the positional argument,
pytest's -m) matches @pytest.mark.<name> markers -- group names (putflag,
getflag, putnoise, getnoise, havoc, exploit, test, stress, misc) and flag
encodings (ascii, utf8) -- as a boolean expression (and/or/not/parens).
--named (pytest's -k) matches individual tests by name. --variant restricts
the run to a single variant id:

    $ enochecker_test "putflag or getflag" ...
    $ enochecker_test "getflag and not utf8" ...
    $ enochecker_test --variant 0 "not exploit" ...
    $ enochecker_test --named test_getflag_twice ...
    $ enochecker_test --named "not offline" --variant 0 putflag ...

markexpr defaults to "not stress and not utf8": the stress tests flood the
checker with hundreds of concurrent tasks, and utf8 flags exercise an encoding
most services never see. Naming any markexpr replaces that default rather than
narrowing it, so spell the exclusions out again to keep them:

    $ enochecker_test stress ...
    $ enochecker_test utf8 ...
    $ enochecker_test "putflag and not stress and not utf8" ...
""",
    )
    parser.add_argument(
        "-a",
        "--checker-address",
        help="The address on which the checker is listening (defaults to the ENOCHECKER_CHECKER_ADDRESS environment variable)",
        default=os.environ.get("ENOCHECKER_CHECKER_ADDRESS", "localhost"),
    )
    parser.add_argument(
        "-n",
        "--checker-network",
        help="The name of the checker docker network to determine the IP from",
        default=os.environ.get("ENOCHECKER_CHECKER_NETWORK"),
    )
    parser.add_argument(
        "-p",
        "--checker-port",
        help="The port on which the checker is listening (defaults to ENOCHECKER_CHECKER_PORT environment variable)",
        choices=range(1, 65536),
        metavar="{1..65535}",
        type=int,
        default=os.environ.get("ENOCHECKER_CHECKER_PORT"),
    )
    parser.add_argument(
        "-A",
        "--service-address",
        help="The address on which the checker can reach the service (defaults to ENOCHECKER_SERVICE_ADDRESS environment variable)",
        default=os.environ.get("ENOCHECKER_SERVICE_ADDRESS"),
    )
    parser.add_argument(
        "-N",
        "--service-network",
        help="The name of the service docker network to determine the IP from",
        default=os.environ.get("ENOCHECKER_SERVICE_NETWORK"),
    )
    parser.add_argument(
        "-m",
        "--multiplier",
        help="Number of times to run for chains with _multiplied methods for",
        type=int,
        default=2,
    )
    parser.add_argument(
        "-s",
        "--seed",
        help="Seed to use for task PRNG (0 = unseeded)",
        type=int,
        default=0,
    )
    parser.add_argument(
        "--exploit-timeout",
        help="Timeout in seconds given to the checker for exploit tasks specifically "
        "(defaults to the same timeout used for all other checker methods, "
        "or ENOCHECKER_EXPLOIT_TIMEOUT if set)",
        type=int,
        default=os.environ.get("ENOCHECKER_EXPLOIT_TIMEOUT"),
    )
    parser.add_argument(
        "-k",
        "--named",
        dest="name_expr",
        metavar="EXPR",
        help="Select individual tests by name in the syntax expected by pytest's "
        "-k flag, e.g. 'test_getflag_twice' or 'not offline'. Composes with "
        "MARKEXPR and --variant: a test must match every filter that is given.",
    )
    parser.add_argument(
        "-v",
        "--variant",
        metavar="ID",
        help="Restrict the run to a single variant id, e.g. only putflag/getflag "
        "variant 0. Applies per checker method, so a run also covers the "
        "_multiplied ids that map onto that variant. Defaults to all variants.",
        type=int,
        default=None,
    )
    parser.add_argument(
        "markexpr",
        metavar="MARKEXPR",
        help="Select tests by marker in the syntax expected by pytest's -m flag, "
        "e.g. 'putflag or getflag', 'not exploit' or 'getflag and utf8'. Markers "
        "are the group names (putflag, getflag, putnoise, getnoise, havoc, "
        "exploit, test, stress, misc) plus the flag encodings (ascii, utf8). "
        "Defaults to 'not stress and not utf8'; naming an expr replaces that "
        "default rather than narrowing it, so the stress and utf8 tests can be "
        "selected back in.",
        nargs="?",
    )

    args = parser.parse_args()

    if args.service_network or args.checker_network:
        import docker

        client = docker.from_env()

        if args.service_network and not args.service_address:
            network = client.networks.get(args.service_network)
            args.service_address = network.attrs["IPAM"]["Config"][0]["Gateway"]

        if args.checker_network and not args.checker_address:
            network = client.networks.get(args.service_network)
            args.checker_address = network.attrs["IPAM"]["Config"][0]["Gateway"]

    if not args.checker_port:
        parser.print_usage()
        raise Exception(
            "Missing enochecker port, please set the ENOCHECKER_CHECKER_PORT environment variable"
        )
    if not args.service_address and not args.service_network:
        parser.print_usage()
        raise Exception(
            "Missing service address, please set the ENOCHECKER_SERVICE_ADDRESS environment variable"
        )

    logging.basicConfig(level=logging.INFO)
    run_tests(
        args.checker_address,
        args.checker_port,
        args.service_address,
        args.markexpr,
        args.multiplier,
        args.seed,
        args.exploit_timeout,
        args.variant,
        args.name_expr,
    )
