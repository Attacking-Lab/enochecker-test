import asyncio
import base64
import hashlib
import secrets
from random import Random, SystemRandom
from typing import Optional

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

global_round_id = 0
FLAG_REGEX_ASCII = r"ENO[A-Za-z0-9+\/=]{48}"
FLAG_REGEX_UTF8 = r"🥺[A-Za-z0-9+\/=]{48}🥺🥺"
REQUEST_TIMEOUT = 10
TEST_REQUEST_TIMEOUT = 3600
CHAIN_ID_PREFIX = secrets.token_hex(20)
# ".invalid" is reserved by RFC 2606 to never resolve, so this reliably
# simulates an unreachable service without depending on network topology.
OFFLINE_ADDRESS = "offline.invalid"

random_source = Random
task_id_random = random_source()


class TaskIdFactory:
    def __init__(self, seed):
        self.rand = random_source(seed)

    def __next__(self):
        return self.rand.randint(0, 1 << 48)


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


@pytest.fixture
def exploit_timeout(request) -> int:
    return request.config.getoption("--exploit-timeout") or REQUEST_TIMEOUT


def pytest_generate_tests(metafunc):
    global task_id_random
    global random_source

    seed: int = metafunc.config.getoption("--seed")
    if seed == 0:
        random_source = SystemRandom
    else:
        random_source = Random
    task_id_random = random_source(seed)

    flag_variants: int = metafunc.config.getoption("--flag-variants")
    noise_variants: int = metafunc.config.getoption("--noise-variants")
    havoc_variants: int = metafunc.config.getoption("--havoc-variants")
    exploit_variants: list[int] = _parse_exploit_variants(
        metafunc.config.getoption("--exploit-variants")
    )
    test_variants: int = metafunc.config.getoption("--test-variants")
    multiplier: int = metafunc.config.getoption("--multiplier")

    if "flag_id" in metafunc.fixturenames:
        metafunc.parametrize("flag_id", range(flag_variants))
    if "flag_id_multiplied" in metafunc.fixturenames:
        metafunc.parametrize(
            "flag_id_multiplied", range(flag_variants, flag_variants * multiplier)
        )
    if "flag_variants" in metafunc.fixturenames:
        metafunc.parametrize("flag_variants", [flag_variants])

    if "noise_id" in metafunc.fixturenames:
        metafunc.parametrize("noise_id", range(noise_variants))
    if "noise_id_multiplied" in metafunc.fixturenames:
        metafunc.parametrize(
            "noise_id_multiplied", range(noise_variants, noise_variants * multiplier)
        )
    if "noise_variants" in metafunc.fixturenames:
        metafunc.parametrize("noise_variants", [noise_variants])

    if "havoc_id" in metafunc.fixturenames:
        metafunc.parametrize("havoc_id", range(havoc_variants))
    if "havoc_id_multiplied" in metafunc.fixturenames:
        metafunc.parametrize(
            "havoc_id_multiplied", range(havoc_variants, havoc_variants * multiplier)
        )
    if "havoc_variants" in metafunc.fixturenames:
        metafunc.parametrize("havoc_variants", [havoc_variants])

    if "exploit_id_multiplied" in metafunc.fixturenames:
        metafunc.parametrize(
            "exploit_id_multiplied",
            range(len(exploit_variants), len(exploit_variants) * multiplier),
        )
    if "exploit_id" in metafunc.fixturenames:
        metafunc.parametrize("exploit_id", range(len(exploit_variants)))

    if "test_id" in metafunc.fixturenames:
        metafunc.parametrize("test_id", range(test_variants))

    if "encoding" in metafunc.fixturenames:
        flag_types = metafunc.config.getoption("--flag-types")
        encodings = [t.strip() for t in flag_types.split(",") if t.strip()]
        metafunc.parametrize("encoding", encodings)

    if "stress_multiplier" in metafunc.fixturenames:
        metafunc.parametrize("stress_multiplier", [32, 128, 512])


def generate_dummyflag(encoding: str) -> str:
    if encoding == "utf8":
        flag = "🥺" + base64.b64encode(secrets.token_bytes(36)).decode() + "🥺🥺"
    else:
        flag = "ENO" + base64.b64encode(secrets.token_bytes(36)).decode()
    assert len(flag) == 51
    return flag


@pytest.fixture
def round_id():
    global global_round_id
    global_round_id += 1
    return global_round_id


@pytest.fixture()
def task_ids():
    return TaskIdFactory(task_id_random.randbytes(8))


def _flag_regex_for_encoding(encoding: str) -> str:
    if encoding == "utf8":
        return FLAG_REGEX_UTF8
    return FLAG_REGEX_ASCII


def _create_request_message(
    method: str,
    task_id: int,
    round_id: int,
    variant_id: int,
    service_address: str,
    flag: Optional[str] = None,
    unique_variant_index: Optional[int] = None,
    flag_regex: Optional[str] = None,
    flag_hash: Optional[str] = None,
    attack_info: Optional[str] = None,
    timeout: Optional[int] = None,
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
    )


async def _execute_request(
    request_message: CheckerTaskMessage,
    checker_url: str,
    expected_result: CheckerTaskResult,
    client: Optional[httpx.AsyncClient],
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
        async with httpx.AsyncClient() as client:
            r = await client.post(
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
) -> Optional[str]:
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
) -> Optional[str]:
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
    encoding, task_ids, round_id, flag_id, service_address, checker_url
):
    flag = generate_dummyflag(encoding)
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
    encoding,
    task_ids,
    round_id,
    flag_id_multiplied,
    flag_variants,
    service_address,
    checker_url: str,
):
    flag = generate_dummyflag(encoding)
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
    encoding,
    task_ids,
    round_id,
    flag_variants,
    service_address,
    checker_url: str,
):
    flag = generate_dummyflag(encoding)
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
async def test_putflag_offline(encoding, task_ids, round_id, flag_id, checker_url):
    flag = generate_dummyflag(encoding)
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
    encoding, task_ids, round_id, flag_id, service_address, checker_url
):
    flag = generate_dummyflag(encoding)
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
    encoding,
    task_ids,
    round_id,
    flag_id,
    flag_variants,
    service_address,
    checker_url,
):
    flag = generate_dummyflag(encoding)
    await _test_putflag(
        flag,
        next(task_ids),
        round_id,
        flag_id,
        service_address,
        checker_url,
    )
    await _test_putflag(
        generate_dummyflag(encoding),
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
    encoding, task_ids, round_id, flag_id, service_address, checker_url
):
    flag = generate_dummyflag(encoding)
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
    encoding, task_ids, round_id, flag_id, service_address, checker_url
):
    flag = generate_dummyflag(encoding)
    await _test_putflag(
        flag,
        next(task_ids),
        round_id,
        flag_id,
        service_address,
        checker_url,
    )
    wrong_flag = generate_dummyflag(encoding)
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
    encoding, task_ids, round_id, flag_id, service_address, checker_url
):
    flag = generate_dummyflag(encoding)
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
    encoding,
    task_ids,
    round_id,
    flag_id_multiplied,
    flag_variants,
    service_address,
    checker_url,
):
    flag = generate_dummyflag(encoding)
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
    encoding,
    task_ids,
    round_id,
    flag_variants,
    service_address,
    checker_url,
):
    flag = generate_dummyflag(encoding)
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
    encoding, task_ids, round_id, flag_id, service_address, checker_url
):
    flag = generate_dummyflag(encoding)
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
    encoding,
    task_ids: TaskIdFactory,
    round_id,
    exploit_id,
    flag_id,
    service_address,
    checker_url: str,
    exploit_timeout: int,
    tries: int = 1,
):
    flag = generate_dummyflag(encoding)
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
            _flag_regex_for_encoding(encoding),
            flag_hash,
            attack_info,
            next(task_ids),
            round_id,
            exploit_id,
            service_address,
            checker_url,
            timeout=exploit_timeout,
        )
        assert found_flag == flag, (
            f"Found flag is incorrect. Expected: {flag}. Found: {found_flag}"
        )


@pytest.mark.exploit
async def test_exploit_per_exploit_id(
    encoding,
    task_ids,
    round_id,
    exploit_id,
    exploit_variants,
    service_address,
    checker_url,
    exploit_timeout,
):
    await _do_exploit_run(
        encoding,
        task_ids,
        round_id,
        exploit_id,
        exploit_variants[exploit_id],
        service_address,
        checker_url,
        exploit_timeout,
    )


@pytest.mark.exploit
async def test_exploit_twice(
    encoding,
    task_ids,
    round_id,
    exploit_id,
    exploit_variants,
    service_address,
    checker_url: str,
    exploit_timeout,
):
    await _do_exploit_run(
        encoding,
        task_ids,
        round_id,
        exploit_id,
        exploit_variants[exploit_id],
        service_address,
        checker_url,
        exploit_timeout,
        tries=2,
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
    encoding,
    task_ids,
    round_id,
    exploit_variants,
    service_address,
    checker_url: str,
):
    flag = generate_dummyflag(encoding)
    flag_hash = hashlib.sha256(flag.encode()).hexdigest()

    await _test_exploit(
        _flag_regex_for_encoding(encoding),
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
    encoding,
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
            flag = generate_dummyflag(encoding)
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
