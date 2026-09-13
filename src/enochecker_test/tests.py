import asyncio
import hashlib
import secrets
from random import Random

import httpx
import jsons
import pytest
from enochecker_core import (
    CheckerInfoMessage,
    CheckerMethod,
    CheckerResultMessage,
    CheckerTaskMessage,
    CheckerTaskResult,
)

from enochecker_test.flagregex import (
    DEFAULT_FLAG_REGEX,
    UnsupportedRegexError,
    generate_from_regex,
)

global_round_id = 0
REQUEST_TIMEOUT = 10
TEST_REQUEST_TIMEOUT = 3600
CHAIN_ID_PREFIX = secrets.token_hex(20)
# ".invalid" is reserved by RFC 2606 to never resolve, so this reliably
# simulates an unreachable service without depending on network topology.
OFFLINE_ADDRESS = "offline.invalid"


class TaskId(int):
    # A task id that also carries the opaque per-task seed enochecker-core's
    # CheckerTaskMessage.seed expects. Subclassing int keeps the ~50 call sites
    # that treat task ids as plain numbers (chain ids, logging, arithmetic)
    # working untouched while letting _create_request_message read .seed off it.
    seed: str

    def __new__(cls, value: int, seed: str) -> "TaskId":  # noqa: PYI034 (typing.Self needs 3.11, project floors at 3.10)
        task_id = super().__new__(cls, value)
        task_id.seed = seed
        return task_id


class TaskIdFactory:
    def __init__(self, seed):
        self.rand = Random(seed)

    def __next__(self) -> TaskId:
        return TaskId(self.rand.randint(0, 1 << 48), self.rand.randbytes(16).hex())


@pytest.fixture
def checker_address(request):
    return request.config.getoption("--checker-address")


@pytest.fixture
def checker_port(request):
    return request.config.getoption("--checker-port")


@pytest.fixture
def service_address(request):
    return request.config.getoption("--service-address")


@pytest.fixture
def checker_url(checker_address, checker_port):
    return f"http://{checker_address}:{checker_port}"


def _parse_exploit_variants(option: str) -> list[int]:
    """The flag variant each exploit targets, indexed by exploit variant id."""
    return [int(variant) for variant in option.split(",") if variant]


@pytest.fixture
def exploit_variants(request) -> list[int]:
    return _parse_exploit_variants(request.config.getoption("--exploit-variants"))


def _parse_patched(option: str) -> set[int]:
    """Exploit variant ids the service under test has already been patched against."""
    return {int(variant) for variant in option.split(",") if variant}


@pytest.fixture
def patched_exploit_ids(request) -> set[int]:
    return _parse_patched(request.config.getoption("--patched"))


@pytest.fixture
def exploit_timeout(request) -> int:
    return request.config.getoption("--exploit-timeout") or REQUEST_TIMEOUT


def _variant_ids(
    count: int, multiplier: int, variant: int | None, multiplied: bool
) -> list[int]:
    """The variant ids a checker method is parametrized over.

    The _multiplied tests use the ids from `count` up to `count * multiplier`;
    a checker maps those back onto a declared variant modulo `count`, which is
    what --variant filters on so it selects the same flagstore in both ranges.
    """
    ids = range(count, count * multiplier) if multiplied else range(count)
    if variant is None:
        return list(ids)
    return [i for i in ids if count and i % count == variant]


def pytest_generate_tests(metafunc):
    flag_variants: int = metafunc.config.getoption("--flag-variants")
    noise_variants: int = metafunc.config.getoption("--noise-variants")
    havoc_variants: int = metafunc.config.getoption("--havoc-variants")
    exploit_variants: list[int] = _parse_exploit_variants(
        metafunc.config.getoption("--exploit-variants")
    )
    test_variants: int = metafunc.config.getoption("--test-variants")
    multiplier: int = metafunc.config.getoption("--multiplier")
    variant: int | None = metafunc.config.getoption("--variant")

    def ids(count: int, multiplied: bool = False) -> list[int]:
        return _variant_ids(count, multiplier, variant, multiplied)

    if "flag_id" in metafunc.fixturenames:
        metafunc.parametrize("flag_id", ids(flag_variants))
    if "flag_id_multiplied" in metafunc.fixturenames:
        metafunc.parametrize("flag_id_multiplied", ids(flag_variants, True))
    if "flag_variants" in metafunc.fixturenames:
        metafunc.parametrize("flag_variants", [flag_variants])

    if "noise_id" in metafunc.fixturenames:
        metafunc.parametrize("noise_id", ids(noise_variants))
    if "noise_id_multiplied" in metafunc.fixturenames:
        metafunc.parametrize("noise_id_multiplied", ids(noise_variants, True))
    if "noise_variants" in metafunc.fixturenames:
        metafunc.parametrize("noise_variants", [noise_variants])

    if "havoc_id" in metafunc.fixturenames:
        metafunc.parametrize("havoc_id", ids(havoc_variants))
    if "havoc_id_multiplied" in metafunc.fixturenames:
        metafunc.parametrize("havoc_id_multiplied", ids(havoc_variants, True))
    if "havoc_variants" in metafunc.fixturenames:
        metafunc.parametrize("havoc_variants", [havoc_variants])

    if "exploit_id_multiplied" in metafunc.fixturenames:
        metafunc.parametrize("exploit_id_multiplied", ids(len(exploit_variants), True))
    if "exploit_id" in metafunc.fixturenames:
        metafunc.parametrize("exploit_id", ids(len(exploit_variants)))

    if "test_id" in metafunc.fixturenames:
        metafunc.parametrize("test_id", ids(test_variants))

    if "stress_multiplier" in metafunc.fixturenames:
        metafunc.parametrize("stress_multiplier", [32, 128, 512])


def generate_dummyflag(flag_regex: str) -> str:
    try:
        return generate_from_regex(flag_regex)
    except UnsupportedRegexError:
        return generate_from_regex(DEFAULT_FLAG_REGEX)


@pytest.fixture
def flag_regex(request) -> str:
    return request.config.getoption("--flag-regex") or DEFAULT_FLAG_REGEX


@pytest.fixture
def round_id():
    global global_round_id
    global_round_id += 1
    return global_round_id


@pytest.fixture()
def task_ids(request):
    # Deriving the stream from the test's own name rather than from a single
    # run-wide sequence keeps a test's task ids independent of which other
    # tests were selected, so replaying one test with the run's seed hands the
    # checker the task ids -- and hence the checker-side RNG -- it saw before.
    seed: str = request.config.getoption("--seed")
    return TaskIdFactory(f"{seed}:{request.node.name}")


def _create_request_message(
    method: str,
    task_id: int,
    round_id: int,
    variant_id: int,
    service_address: str,
    flag: str | None = None,
    unique_variant_index: int | None = None,
    flag_regex: str | None = None,
    flag_hash: str | None = None,
    attack_info: str | None = None,
    timeout: int | None = None,
) -> CheckerTaskMessage:
    if unique_variant_index is None:
        unique_variant_index = variant_id

    prefix = "havoc"
    if method in ("putflag", "getflag"):
        prefix = "flag"
    elif method in ("putnoise", "getnoise"):
        prefix = "noise"
    elif method == "exploit":
        prefix = "exploit"
    task_chain_id = (
        f"{CHAIN_ID_PREFIX}_{prefix}_s0_r{round_id}_t0_i{unique_variant_index}"
    )

    return CheckerTaskMessage(
        task_id=task_id,
        method=CheckerMethod(method),
        address=service_address,
        team_id=0,
        team_name="teamname",
        current_round_id=round_id,
        related_round_id=round_id,
        flag=flag,
        variant_id=variant_id,
        timeout=timeout if timeout is not None else REQUEST_TIMEOUT * 1000,
        round_length=60000,
        task_chain_id=task_chain_id,
        flag_regex=flag_regex,
        flag_hash=flag_hash,
        attack_info=attack_info,
        seed=getattr(task_id, "seed", None),
    )


async def _execute_request(
    request_message: CheckerTaskMessage,
    checker_url: str,
    expected_result: CheckerTaskResult,
    client: httpx.AsyncClient | None,
) -> CheckerResultMessage:
    # The checker holds the connection open for the full task, so the HTTP
    # client has to wait at least as long as the timeout given to the checker.
    http_timeout = max(REQUEST_TIMEOUT, request_message.timeout / 1000)
    if client is not None:
        r = await client.post(
            f"{checker_url}",
            json=request_message.model_dump(),
            timeout=http_timeout,
        )
    else:
        async with httpx.AsyncClient() as owned_client:
            r = await owned_client.post(
                f"{checker_url}",
                json=request_message.model_dump(),
                timeout=http_timeout,
            )
    print(r.content)
    result_message: CheckerResultMessage = CheckerResultMessage.model_validate_json(
        r.content
    )
    assert CheckerTaskResult(result_message.result) == expected_result, (
        f"\nMessage: {result_message.message}\n"
    )
    return result_message


async def _test_putflag(
    flag,
    task_id,
    round_id,
    flag_id,
    service_address,
    checker_url,
    unique_variant_index=None,
    expected_result=CheckerTaskResult.OK,
    client=None,
) -> str | None:
    if unique_variant_index is None:
        unique_variant_index = flag_id
    request_message = _create_request_message(
        "putflag",
        task_id,
        round_id,
        flag_id,
        service_address,
        flag,
        unique_variant_index=unique_variant_index,
    )
    result_message: CheckerResultMessage = await _execute_request(
        request_message, checker_url, expected_result, client
    )
    return result_message.attack_info


async def _test_getflag(
    flag,
    task_id,
    round_id,
    flag_id,
    service_address,
    checker_url,
    unique_variant_index=None,
    expected_result=CheckerTaskResult.OK,
    client=None,
):
    if unique_variant_index is None:
        unique_variant_index = flag_id
    request_message = _create_request_message(
        "getflag",
        task_id,
        round_id,
        flag_id,
        service_address,
        flag,
        unique_variant_index=unique_variant_index,
    )
    await _execute_request(request_message, checker_url, expected_result, client)


async def _test_putnoise(
    task_id,
    round_id,
    noise_id,
    service_address,
    checker_url,
    unique_variant_index=None,
    expected_result=CheckerTaskResult.OK,
    client=None,
):
    if unique_variant_index is None:
        unique_variant_index = noise_id
    request_message = _create_request_message(
        "putnoise",
        task_id,
        round_id,
        noise_id,
        service_address,
        unique_variant_index=unique_variant_index,
    )
    await _execute_request(request_message, checker_url, expected_result, client)


async def _test_getnoise(
    task_id,
    round_id,
    noise_id,
    service_address,
    checker_url,
    unique_variant_index=None,
    expected_result=CheckerTaskResult.OK,
    client=None,
):
    if unique_variant_index is None:
        unique_variant_index = noise_id
    request_message = _create_request_message(
        "getnoise",
        task_id,
        round_id,
        noise_id,
        service_address,
        unique_variant_index=unique_variant_index,
    )
    await _execute_request(request_message, checker_url, expected_result, client)


async def _test_havoc(
    task_id,
    round_id,
    havoc_id,
    service_address,
    checker_url,
    unique_variant_index=None,
    expected_result=CheckerTaskResult.OK,
    client=None,
):
    if unique_variant_index is None:
        unique_variant_index = havoc_id
    request_message = _create_request_message(
        "havoc",
        task_id,
        round_id,
        havoc_id,
        service_address,
        unique_variant_index=unique_variant_index,
    )
    await _execute_request(request_message, checker_url, expected_result, client)


async def _test_exploit(
    flag_regex,
    flag_hash,
    attack_info,
    task_id,
    round_id,
    exploit_id,
    service_address,
    checker_url,
    unique_variant_index=None,
    expected_result=CheckerTaskResult.OK,
    client=None,
    timeout=None,
) -> str | None:
    if unique_variant_index is None:
        unique_variant_index = exploit_id
    request_message = _create_request_message(
        "exploit",
        task_id,
        round_id,
        exploit_id,
        service_address,
        unique_variant_index=unique_variant_index,
        flag_regex=flag_regex,
        flag_hash=flag_hash,
        attack_info=attack_info,
        timeout=timeout * 1000 if timeout is not None else None,
    )
    result_message: CheckerResultMessage = await _execute_request(
        request_message, checker_url, expected_result, client
    )
    return result_message.flag


async def _test_test(
    task_id,
    round_id,
    test_id,
    service_address,
    checker_url,
    unique_variant_index=None,
    expected_result=CheckerTaskResult.OK,
    client=None,
):
    if unique_variant_index is None:
        unique_variant_index = test_id
    request_message = _create_request_message(
        "test",
        task_id,
        round_id,
        test_id,
        service_address,
        unique_variant_index=unique_variant_index,
        timeout=TEST_REQUEST_TIMEOUT * 1000,
    )
    await _execute_request(request_message, checker_url, expected_result, client)


@pytest.mark.putflag
async def test_putflag(
    flag_regex, task_ids, round_id, flag_id, service_address, checker_url
):
    flag = generate_dummyflag(flag_regex)
    await _test_putflag(
        flag,
        next(task_ids),
        round_id,
        flag_id,
        service_address,
        checker_url,
    )


@pytest.mark.putflag
async def test_putflag_multiplied(
    flag_regex,
    task_ids,
    round_id,
    flag_id_multiplied,
    flag_variants,
    service_address,
    checker_url: str,
):
    flag = generate_dummyflag(flag_regex)
    await _test_putflag(
        flag,
        next(task_ids),
        round_id,
        flag_id_multiplied % flag_variants,
        service_address,
        checker_url,
        unique_variant_index=flag_id_multiplied,
    )


@pytest.mark.putflag
async def test_putflag_invalid_variant(
    flag_regex,
    task_ids,
    round_id,
    flag_variants,
    service_address,
    checker_url: str,
):
    flag = generate_dummyflag(flag_regex)
    await _test_putflag(
        flag,
        next(task_ids),
        round_id,
        flag_variants,
        service_address,
        checker_url,
        expected_result=CheckerTaskResult.INTERNAL_ERROR,
    )


@pytest.mark.putflag
async def test_putflag_offline(flag_regex, task_ids, round_id, flag_id, checker_url):
    flag = generate_dummyflag(flag_regex)
    await _test_putflag(
        flag,
        next(task_ids),
        round_id,
        flag_id,
        OFFLINE_ADDRESS,
        checker_url,
        expected_result=CheckerTaskResult.OFFLINE,
    )


@pytest.mark.getflag
async def test_getflag(
    flag_regex, task_ids, round_id, flag_id, service_address, checker_url
):
    flag = generate_dummyflag(flag_regex)
    await _test_putflag(
        flag,
        next(task_ids),
        round_id,
        flag_id,
        service_address,
        checker_url,
    )
    await _test_getflag(
        flag,
        next(task_ids),
        round_id,
        flag_id,
        service_address,
        checker_url,
    )


@pytest.mark.getflag
async def test_getflag_after_second_putflag_with_same_variant_id(
    flag_regex,
    task_ids,
    round_id,
    flag_id,
    flag_variants,
    service_address,
    checker_url,
):
    flag = generate_dummyflag(flag_regex)
    await _test_putflag(
        flag,
        next(task_ids),
        round_id,
        flag_id,
        service_address,
        checker_url,
    )
    await _test_putflag(
        generate_dummyflag(flag_regex),
        next(task_ids),
        round_id,
        flag_id,
        service_address,
        checker_url,
        unique_variant_index=flag_id + flag_variants,
    )
    await _test_getflag(
        flag,
        next(task_ids),
        round_id,
        flag_id,
        service_address,
        checker_url,
    )


@pytest.mark.getflag
async def test_getflag_twice(
    flag_regex, task_ids, round_id, flag_id, service_address, checker_url
):
    flag = generate_dummyflag(flag_regex)
    await _test_putflag(
        flag,
        next(task_ids),
        round_id,
        flag_id,
        service_address,
        checker_url,
    )
    await _test_getflag(
        flag,
        next(task_ids),
        round_id,
        flag_id,
        service_address,
        checker_url,
    )
    await _test_getflag(
        flag,
        next(task_ids),
        round_id,
        flag_id,
        service_address,
        checker_url,
    )


@pytest.mark.getflag
async def test_getflag_wrong_flag(
    flag_regex, task_ids, round_id, flag_id, service_address, checker_url
):
    flag = generate_dummyflag(flag_regex)
    await _test_putflag(
        flag,
        next(task_ids),
        round_id,
        flag_id,
        service_address,
        checker_url,
    )
    wrong_flag = generate_dummyflag(flag_regex)
    await _test_getflag(
        wrong_flag,
        next(task_ids),
        round_id,
        flag_id,
        service_address,
        checker_url,
        expected_result=CheckerTaskResult.MUMBLE,
    )


@pytest.mark.getflag
async def test_getflag_without_putflag(
    flag_regex, task_ids, round_id, flag_id, service_address, checker_url
):
    flag = generate_dummyflag(flag_regex)
    await _test_getflag(
        flag,
        next(task_ids),
        round_id,
        flag_id,
        service_address,
        checker_url,
        expected_result=CheckerTaskResult.MUMBLE,
    )


@pytest.mark.getflag
async def test_getflag_multiplied(
    flag_regex,
    task_ids,
    round_id,
    flag_id_multiplied,
    flag_variants,
    service_address,
    checker_url,
):
    flag = generate_dummyflag(flag_regex)
    await _test_putflag(
        flag,
        next(task_ids),
        round_id,
        flag_id_multiplied % flag_variants,
        service_address,
        checker_url,
        unique_variant_index=flag_id_multiplied,
    )
    await _test_getflag(
        flag,
        next(task_ids),
        round_id,
        flag_id_multiplied % flag_variants,
        service_address,
        checker_url,
        unique_variant_index=flag_id_multiplied,
    )


@pytest.mark.getflag
async def test_getflag_invalid_variant(
    flag_regex,
    task_ids,
    round_id,
    flag_variants,
    service_address,
    checker_url,
):
    flag = generate_dummyflag(flag_regex)
    await _test_getflag(
        flag,
        next(task_ids),
        round_id,
        flag_variants,
        service_address,
        checker_url,
        expected_result=CheckerTaskResult.INTERNAL_ERROR,
    )


@pytest.mark.getflag
async def test_getflag_offline(
    flag_regex, task_ids, round_id, flag_id, service_address, checker_url
):
    flag = generate_dummyflag(flag_regex)
    await _test_putflag(
        flag,
        next(task_ids),
        round_id,
        flag_id,
        service_address,
        checker_url,
    )
    await _test_getflag(
        flag,
        next(task_ids),
        round_id,
        flag_id,
        OFFLINE_ADDRESS,
        checker_url,
        expected_result=CheckerTaskResult.OFFLINE,
    )


@pytest.mark.putnoise
async def test_putnoise(round_id, task_ids, noise_id, service_address, checker_url):
    await _test_putnoise(
        next(task_ids),
        round_id,
        noise_id,
        service_address,
        checker_url,
    )


@pytest.mark.putnoise
async def test_putnoise_multiplied(
    task_ids,
    round_id,
    noise_id_multiplied,
    noise_variants,
    service_address,
    checker_url,
):
    await _test_putnoise(
        next(task_ids),
        round_id,
        noise_id_multiplied % noise_variants,
        service_address,
        checker_url,
        unique_variant_index=noise_id_multiplied,
    )


@pytest.mark.putnoise
async def test_putnoise_invalid_variant(
    task_ids, round_id, noise_variants, service_address, checker_url
):
    await _test_putnoise(
        next(task_ids),
        round_id,
        noise_variants,
        service_address,
        checker_url,
        expected_result=CheckerTaskResult.INTERNAL_ERROR,
    )


@pytest.mark.putnoise
async def test_putnoise_offline(task_ids, round_id, noise_id, checker_url):
    await _test_putnoise(
        next(task_ids),
        round_id,
        noise_id,
        OFFLINE_ADDRESS,
        checker_url,
        expected_result=CheckerTaskResult.OFFLINE,
    )


@pytest.mark.getnoise
async def test_getnoise(task_ids, round_id, noise_id, service_address, checker_url):
    await _test_putnoise(
        next(task_ids),
        round_id,
        noise_id,
        service_address,
        checker_url,
    )
    await _test_getnoise(
        next(task_ids),
        round_id,
        noise_id,
        service_address,
        checker_url,
    )


@pytest.mark.getnoise
async def test_getnoise_after_second_putnoise_with_same_variant_id(
    task_ids,
    round_id,
    noise_id,
    noise_variants,
    service_address,
    checker_url,
):
    await _test_putnoise(
        next(task_ids),
        round_id,
        noise_id,
        service_address,
        checker_url,
    )
    await _test_putnoise(
        next(task_ids),
        round_id,
        noise_id,
        service_address,
        checker_url,
        unique_variant_index=noise_id + noise_variants,
    )
    await _test_getnoise(
        next(task_ids),
        round_id,
        noise_id,
        service_address,
        checker_url,
    )


@pytest.mark.getnoise
async def test_getnoise_twice(
    task_ids, round_id, noise_id, service_address, checker_url
):
    await _test_putnoise(
        next(task_ids),
        round_id,
        noise_id,
        service_address,
        checker_url,
    )
    await _test_getnoise(
        next(task_ids),
        round_id,
        noise_id,
        service_address,
        checker_url,
    )
    await _test_getnoise(
        next(task_ids),
        round_id,
        noise_id,
        service_address,
        checker_url,
    )


@pytest.mark.getnoise
async def test_getnoise_without_putnoise(
    task_ids, round_id, noise_id, service_address, checker_url
):
    await _test_getnoise(
        next(task_ids),
        round_id,
        noise_id,
        service_address,
        checker_url,
        expected_result=CheckerTaskResult.MUMBLE,
    )


@pytest.mark.getnoise
async def test_getnoise_multiplied(
    task_ids,
    round_id,
    noise_id_multiplied,
    noise_variants,
    service_address,
    checker_url,
):
    await _test_putnoise(
        next(task_ids),
        round_id,
        noise_id_multiplied % noise_variants,
        service_address,
        checker_url,
        unique_variant_index=noise_id_multiplied,
    )
    await _test_getnoise(
        next(task_ids),
        round_id,
        noise_id_multiplied % noise_variants,
        service_address,
        checker_url,
        unique_variant_index=noise_id_multiplied,
    )


@pytest.mark.getnoise
async def test_getnoise_invalid_variant(
    task_ids: TaskIdFactory,
    round_id: int,
    noise_variants: int,
    service_address: str,
    checker_url: str,
):
    await _test_getnoise(
        next(task_ids),
        round_id,
        noise_variants,
        service_address,
        checker_url,
        expected_result=CheckerTaskResult.INTERNAL_ERROR,
    )


@pytest.mark.getnoise
async def test_getnoise_offline(
    task_ids, round_id, noise_id, service_address, checker_url
):
    await _test_putnoise(
        next(task_ids),
        round_id,
        noise_id,
        service_address,
        checker_url,
    )
    await _test_getnoise(
        next(task_ids),
        round_id,
        noise_id,
        OFFLINE_ADDRESS,
        checker_url,
        expected_result=CheckerTaskResult.OFFLINE,
    )


@pytest.mark.havoc
async def test_havoc(task_ids, round_id, havoc_id, service_address, checker_url):
    await _test_havoc(
        next(task_ids),
        round_id,
        havoc_id,
        service_address,
        checker_url,
    )


@pytest.mark.havoc
async def test_havoc_multiplied(
    task_ids: TaskIdFactory,
    round_id: int,
    havoc_id_multiplied: int,
    havoc_variants: int,
    service_address: str,
    checker_url: str,
):
    await _test_havoc(
        next(task_ids),
        round_id,
        havoc_id_multiplied % havoc_variants,
        service_address,
        checker_url,
        unique_variant_index=havoc_id_multiplied,
    )


@pytest.mark.havoc
async def test_havoc_invalid_variant(
    task_ids, round_id, havoc_variants, service_address, checker_url
):
    await _test_havoc(
        next(task_ids),
        round_id,
        havoc_variants,
        service_address,
        checker_url,
        expected_result=CheckerTaskResult.INTERNAL_ERROR,
    )


@pytest.mark.havoc
async def test_havoc_offline(task_ids, round_id, havoc_id, checker_url):
    await _test_havoc(
        next(task_ids),
        round_id,
        havoc_id,
        OFFLINE_ADDRESS,
        checker_url,
        expected_result=CheckerTaskResult.OFFLINE,
    )


async def _do_exploit_run(
    flag_regex,
    task_ids: TaskIdFactory,
    round_id,
    exploit_id,
    flag_id,
    service_address,
    checker_url: str,
    exploit_timeout: int,
    tries: int = 1,
    patched: bool = False,
):
    flag = generate_dummyflag(flag_regex)
    flag_hash = hashlib.sha256(flag.encode()).hexdigest()

    attack_info = await _test_putflag(
        flag,
        next(task_ids),
        round_id,
        flag_id,
        service_address,
        checker_url,
    )
    for _ in range(tries):
        found_flag = await _test_exploit(
            flag_regex,
            flag_hash,
            attack_info,
            next(task_ids),
            round_id,
            exploit_id,
            service_address,
            checker_url,
            # A patched service no longer yields the flag, so enochecker3
            # finds none and reports MUMBLE rather than OK; expecting OK would
            # fail on the result before the flag is ever compared. An exploit
            # that still returns OK here means the patch did not close it.
            expected_result=(
                CheckerTaskResult.MUMBLE if patched else CheckerTaskResult.OK
            ),
            timeout=exploit_timeout,
        )
        if patched:
            assert found_flag != flag, (
                f"Exploit variant {exploit_id} is marked --patched but still "
                f"recovered the correct flag: {flag}"
            )
        else:
            assert found_flag == flag, (
                f"Found flag is incorrect. Expected: {flag}. Found: {found_flag}"
            )


@pytest.mark.exploit
async def test_exploit_per_exploit_id(
    flag_regex,
    task_ids,
    round_id,
    exploit_id,
    exploit_variants,
    service_address,
    checker_url,
    exploit_timeout,
    patched_exploit_ids,
):
    await _do_exploit_run(
        flag_regex,
        task_ids,
        round_id,
        exploit_id,
        exploit_variants[exploit_id],
        service_address,
        checker_url,
        exploit_timeout,
        patched=exploit_id in patched_exploit_ids,
    )


@pytest.mark.exploit
async def test_exploit_twice(
    flag_regex,
    task_ids,
    round_id,
    exploit_id,
    exploit_variants,
    service_address,
    checker_url: str,
    exploit_timeout,
    patched_exploit_ids,
):
    await _do_exploit_run(
        flag_regex,
        task_ids,
        round_id,
        exploit_id,
        exploit_variants[exploit_id],
        service_address,
        checker_url,
        exploit_timeout,
        tries=2,
        patched=exploit_id in patched_exploit_ids,
    )


@pytest.mark.exploit
async def test_all_flagstores_exploitable(
    flag_variants,
    exploit_variants,
):
    missing = sorted(set(range(flag_variants)) - set(exploit_variants))
    assert not missing, f"No exploit defined for flag variant(s): {missing}"


@pytest.mark.exploit
async def test_exploit_invalid_variant(
    flag_regex,
    task_ids,
    round_id,
    exploit_variants,
    service_address,
    checker_url: str,
):
    flag = generate_dummyflag(flag_regex)
    flag_hash = hashlib.sha256(flag.encode()).hexdigest()

    await _test_exploit(
        flag_regex,
        flag_hash,
        None,
        next(task_ids),
        round_id,
        len(exploit_variants),
        service_address,
        checker_url,
        expected_result=CheckerTaskResult.INTERNAL_ERROR,
    )


@pytest.mark.misc
async def test_checker_info_message_case(
    checker_url,
):
    async with httpx.AsyncClient() as client:
        r = await client.get(
            f"{checker_url}/service",
            timeout=REQUEST_TIMEOUT,
        )
    assert r.status_code == 200
    camelcase_json = jsons.dumps(
        r.json(), key_transformer=jsons.KEY_TRANSFORMER_CAMELCASE, sort_keys=True
    )
    assert jsons.dumps(r.json(), sort_keys=True) == camelcase_json
    info_message = CheckerInfoMessage.model_validate_json(r.text)
    assert r.json() == info_message.model_dump(by_alias=True)


@pytest.mark.test
async def test_test(task_ids, round_id, test_id, service_address, checker_url):
    await _test_test(
        next(task_ids),
        round_id,
        test_id,
        service_address,
        checker_url,
    )


@pytest.mark.stress
async def test_stress(
    flag_regex,
    task_ids,
    round_id,
    flag_variants,
    noise_variants,
    havoc_variants,
    service_address,
    checker_url,
    stress_multiplier,
):
    transport = httpx.AsyncHTTPTransport(
        limits=httpx.Limits(max_connections=1000, max_keepalive_connections=200)
    )
    async with httpx.AsyncClient(transport=transport) as client:

        async def flag_fn(i, flag_id):
            flag = generate_dummyflag(flag_regex)
            await _test_putflag(
                flag,
                next(task_ids),
                round_id,
                flag_id,
                service_address,
                checker_url,
                unique_variant_index=i * flag_variants + flag_id,
                client=client,
            )

        async def noise_fn(i, noise_id):
            await _test_putnoise(
                next(task_ids),
                round_id,
                noise_id,
                service_address,
                checker_url,
                unique_variant_index=i * noise_variants + noise_id,
                client=client,
            )

        async def havoc_fn(i, havoc_id):
            await _test_havoc(
                next(task_ids),
                round_id,
                havoc_id,
                service_address,
                checker_url,
                unique_variant_index=i * havoc_variants + havoc_id,
                client=client,
            )

        awaitables = []
        for i in range(stress_multiplier):
            for flag_id in range(flag_variants):
                awaitables.append(flag_fn(i, flag_id))
            for noise_id in range(noise_variants):
                awaitables.append(noise_fn(i, noise_id))
            for havoc_id in range(havoc_variants):
                awaitables.append(havoc_fn(i, havoc_id))

        await asyncio.gather(*awaitables)
