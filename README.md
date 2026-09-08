# enochecker_test

Automatically test services/checker using the enochecker API

# Usage
`enochecker_test` runs tests against a checker. Which tests run is selected by the positional `MARKEXPR` argument, by `-k`/`--named` and by `-v`/`--variant`.

Every test is annotated with the checker method it exercises (`putflag`, `getflag`, `putnoise`, `getnoise`, `havoc`, `exploit`, `test`, plus `stress` and `misc` for the tests that don't map to a single method) via `@pytest.mark.<name>`. Tests that plant or read a flag additionally run once per flag encoding and carry that encoding's name as a marker (`ascii`, `utf8`). `MARKEXPR` selects over those markers using the boolean expression syntax pytest's own `-m` flag expects (`and`/`or`/`not`/parens); it maps straight onto `-m` under the hood:

```
$ enochecker_test "putflag or getflag" ...
$ enochecker_test "not exploit" ...
$ enochecker_test "getflag and utf8" ...
```

`MARKEXPR` defaults to `not stress and not utf8`: the stress tests flood the checker with hundreds of concurrent tasks, and utf8 flags exercise an encoding most services never see, so both are opt-in. Naming an expression **replaces** that default rather than narrowing it — spell the exclusions out again to keep them:

```
$ enochecker_test stress ...
$ enochecker_test utf8 ...
$ enochecker_test "putflag and not stress and not utf8" ...
```

`-v`/`--variant ID` narrows the run to a single variant id, orthogonally to `MARKEXPR`. It applies per checker method, and also picks up the `_multiplied` ids that map onto that variant (id `i` belongs to variant `i % <method>_variants`), so it consistently exercises one flagstore end to end:

```
$ enochecker_test --variant 0 ...
$ enochecker_test --variant 1 "putflag or getflag" ...
```

`-k`/`--named EXPR` selects individual tests by name, mapping onto pytest's `-k`. Use it to reach a specific test that no marker singles out:

```
$ enochecker_test --named test_getflag_twice ...
$ enochecker_test --named "not offline" ...
```

`--patched ID[,ID...]` marks one or more exploit variant ids as already patched in the service under test. For those ids, `test_exploit_per_exploit_id` and `test_exploit_twice` invert their assertion: they expect the exploit to fail to recover the flag, and fail the run if it still does. Use this to confirm a fix actually closes that exploit variant, rather than treating a still-working exploit as a passing test:

```
$ enochecker_test --patched 0 exploit ...
$ enochecker_test --patched 0,2 exploit ...
```

The filters are independent and compose — a test runs only if it matches every one that was given:

```
$ enochecker_test --named "not offline" --variant 0 "putflag or getflag" ...
```

Each run seeds the task-id PRNG with a fresh random seed and prints it in the run header:

```
seed: a85def42c911d737
```

Pass it back with `-s`/`--seed` to repeat the task ids a run used:

```
$ enochecker_test --seed a85def42c911d737 ...
```

A test's task ids are derived from the seed and the test's own name, so they don't depend on which other tests were selected — replaying a single failing test under the run's seed gives it the same task ids it had in the full run. Each task also carries a `seed` field: opaque per-task entropy derived from the run seed and distinct from `task_id`. enochecker3 seeds its per-task `Random` from `task.seed`, so replaying under the run's seed reproduces the same random inputs. Flags are not derived from the seed and differ on every run.

```
usage: enochecker_test [-h] [-a CHECKER_ADDRESS] [-n CHECKER_NETWORK] [-p {1..65535}]
                       [-A SERVICE_ADDRESS] [-N SERVICE_NETWORK] [-m MULTIPLIER] [-s SEED]
                       [--exploit-timeout EXPLOIT_TIMEOUT] [-k EXPR] [-v ID]
                       [--patched ID[,ID...]]
                       [MARKEXPR]

Utility for testing checkers that implement the enochecker API

positional arguments:
  MARKEXPR              Select tests by marker in the syntax expected by pytest's -m flag, e.g.
                        'putflag or getflag', 'not exploit' or 'getflag and utf8'. Markers are the
                        group names (putflag, getflag, putnoise, getnoise, havoc, exploit, test,
                        stress, misc) plus the flag encodings (ascii, utf8). Defaults to the
                        ENOCHECKER_MARK_EXPR environment variable, or to 'not stress and not utf8'
                        if that is unset; naming an expr replaces that default rather than
                        narrowing it, so the stress and utf8 tests can be selected back in.

options:
  -h, --help            show this help message and exit
  -a, --checker-address CHECKER_ADDRESS
                        The address on which the checker is listening (defaults to the
                        ENOCHECKER_CHECKER_ADDRESS environment variable)
  -n, --checker-network CHECKER_NETWORK
                        The name of the checker docker network to determine the IP from
  -p, --checker-port {1..65535}
                        The port on which the checker is listening (defaults to
                        ENOCHECKER_CHECKER_PORT environment variable)
  -A, --service-address SERVICE_ADDRESS
                        The address on which the checker can reach the service (defaults to
                        ENOCHECKER_SERVICE_ADDRESS environment variable)
  -N, --service-network SERVICE_NETWORK
                        The name of the service docker network to determine the IP from
  -m, --multiplier MULTIPLIER
                        Number of times to run for chains with _multiplied methods for
  -s, --seed SEED       Seed to use for the task PRNG, as printable text. Defaults to a fresh
                        random seed per run, which is printed in the run header so it can be
                        passed back in to repeat that run's task ids
  --exploit-timeout EXPLOIT_TIMEOUT
                        Timeout in seconds given to the checker for exploit tasks specifically
                        (defaults to the same timeout used for all other checker methods, or
                        ENOCHECKER_EXPLOIT_TIMEOUT if set)
  -k, --named EXPR      Select individual tests by name in the syntax expected by pytest's -k
                        flag, e.g. 'test_getflag_twice' or 'not offline'. Composes with MARKEXPR
                        and --variant: a test must match every filter that is given.
  -v, --variant ID      Restrict the run to a single variant id, e.g. only putflag/getflag variant
                        0. Applies per checker method, so a run also covers the _multiplied ids
                        that map onto that variant. Defaults to all variants.
  --patched ID[,ID...]  Comma-separated exploit variant id(s) that are already patched in the
                        service under test. For those ids, test_exploit_per_exploit_id and
                        test_exploit_twice invert their assertion and expect the exploit to fail
                        to recover the flag, instead of failing the run when it does. Use this to
                        confirm a fix actually closes that exploit variant.

Example Usage:

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

markexpr defaults to ENOCHECKER_MARK_EXPR, or to "not stress and not utf8"
when that is unset: the stress tests flood the checker with hundreds of
concurrent tasks, and utf8 flags exercise an encoding most services never see.
Naming any markexpr replaces that default rather than narrowing it, so spell
the exclusions out again to keep them:

    $ enochecker_test stress ...
    $ enochecker_test utf8 ...
    $ enochecker_test "putflag and not stress and not utf8" ...
```
