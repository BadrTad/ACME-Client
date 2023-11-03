import pytest
import httpx
import subprocess, psutil

from time import sleep
from acme_http import ACME_HTTP

from jws.jws import JWSFactory

from method.nonce import get_nonce
from method.directory.fetch_directory import fetch_directory
from method.account.create_account import create_account
from method.order.order_methods import (
    check_order,
    create_order,
    finalize_order,
)
from method.certificate import (
    dowload_certificate,
    revoke_certificate,
)
from method.order.fetch_authorization import (
    fetch_authorization,
    respond_to_challenge,
    solve_dns_challenge,
    solve_http_challenge,
)
from acme_dns import ACME_DNS

from acme_types import URL, Nonce

from acme_debug import (
    PROXIES,
    URL_ACME_DIR,
    URL_ACCOUNT_RESOURCE,
    URL_NEW_ORDER_RESOURSE,
    URL_NONCE_RESOURCE,
    URL_REVOKE_CERTIFICATE_RESOURCE,
    get_debug_jws_factory,
)
from validation import *


@pytest.fixture(scope="function", autouse=True)
def pebble_server_setup_teardown():
    cmd = "PEBBLE_WFE_NONCEREJECT=0 pebble -dnsserver 127.0.0.1:5053"

    process = subprocess.Popen(cmd, cwd="/usr/local/pebble", shell=True)
    yield  # This allows the test functions to run

    for child in psutil.Process(process.pid).children(recursive=True):
        child.kill()
    process.kill()


@pytest.fixture(autouse=True)
def jws_factory() -> JWSFactory:
    return get_debug_jws_factory(new=False)


@pytest.fixture()
def nonce(client) -> Nonce:
    nonce = get_nonce(client, URL_NONCE_RESOURCE)
    if not is_valid_nonce(nonce):
        raise Exception("Error getting valid nonce")
    return nonce


@pytest.fixture()
def identifiers() -> list[Identifier]:
    return [
        Identifier({"type": "dns", "value": "syssec.ethz.ch"}),
        # Identifier({"type": "dns", "value": "netsec.ethz.ch"}),
        # Identifier({"type": "dns", "value": "www.epfl.ch"}),
    ]


@pytest.fixture()
def acme_dns(identifiers) -> ACME_DNS:
    dns_server: ACME_DNS = ACME_DNS()
    dns_server.start()
    yield dns_server

    # Remove all the added records from TOML
    for identifier in identifiers:
        dns_server.remove_record(identifier.value)

    dns_server.stop()


@pytest.fixture()
def acme_http(acme_dns: ACME_DNS):
    acme_http = ACME_HTTP("127.0.0.1", 5002)
    acme_http.run()
    yield acme_http
    acme_http.stop()


@pytest.fixture(name="client")
def acme_client():
    client = httpx.Client(http2=True, verify=False, proxies=PROXIES)
    # client = httpx.Client(http2=True, verify=config.PATH_PEBBLE_CERTIFICATE)
    yield client
    client.close()


@pytest.mark.run(order=1)
def test_directory(client):
    try:
        j = fetch_directory(client, URL_ACME_DIR)
        assert not is_json_error(j)
    except Exception as e:
        print(e)
        assert False


@pytest.mark.run(order=1)
def test_nonce(client):
    try:
        nonce = get_nonce(client, URL_NONCE_RESOURCE)
        assert is_valid_nonce(nonce)
        assert len(nonce) > 0
    except Exception as e:
        print(e)
        assert False


@pytest.mark.run(order=1)
def test_account_creation(client, nonce: Nonce, jws_factory: JWSFactory):
    try:
        account, new_nonce = create_account(
            client, URL_ACCOUNT_RESOURCE, nonce, jws_factory
        )
        account.status == "valid"
        assert is_valid_kid(account.kid)
        account.contact is list
        len(account.contact) > 0

        assert is_valid_nonce(new_nonce)

    except Exception as e:
        print(e)
        assert False


@pytest.mark.run(order=1)
def test_order_creation(
    client, identifiers: list[Identifier], nonce: Nonce, jws_factory: JWSFactory
):
    # First we create an order
    account, nonce = create_account(client, URL_ACCOUNT_RESOURCE, nonce, jws_factory)

    try:
        orders, new_nonce = create_order(
            client, URL_NEW_ORDER_RESOURSE, account.kid, nonce, identifiers, jws_factory
        )
        assert orders.is_still_pending()
        assert are_valid_identifiers(identifiers, orders.identifiers)
        assert is_valid_finalize(orders.finalize)
        assert are_valid_authorizations(orders.authorizations)
        assert is_valid_expires(orders.expires)
        assert is_valid_order_url(orders.order_url)
        assert orders.orders is None
        assert is_valid_nonce(new_nonce)

    except Exception as e:
        print(e)
        assert False


@pytest.mark.run(order=2)
def test_challenges_for_authorization(
    client, identifiers: list[Identifier], nonce: Nonce, jws_factory: JWSFactory
):
    account, nonce = create_account(client, URL_ACCOUNT_RESOURCE, nonce, jws_factory)

    orders, nonce = create_order(
        client, URL_NEW_ORDER_RESOURSE, account.kid, nonce, identifiers, jws_factory
    )

    def assert_authorization(auth_url: URL, nonce) -> bool:
        authorization, new_nonce = fetch_authorization(
            client, account.kid, auth_url, nonce, jws_factory
        )
        assert authorization.is_still_pending()
        assert authorization.identifier in orders.identifiers
        assert (
            authorization.challenges is not None and len(authorization.challenges) > 0
        )
        assert are_valid_challenges(authorization.challenges)
        assert is_valid_expires(authorization.expires)
        assert is_valid_nonce(nonce)
        return new_nonce

    for auth_url in orders.authorizations:
        nonce = assert_authorization(auth_url, nonce)


# @pytest.mark.skip(reason="Known correct")
def test_dns_challenge_validation(
    client,
    acme_dns: ACME_DNS,
    identifiers: list[Identifier],
    nonce: Nonce,
    jws_factory: JWSFactory,
):
    account, nonce = create_account(client, URL_ACCOUNT_RESOURCE, nonce, jws_factory)
    orders, nonce = create_order(
        client, URL_NEW_ORDER_RESOURSE, account.kid, nonce, identifiers, jws_factory
    )

    auth_url = orders.authorizations[0]
    authorization, nonce = fetch_authorization(
        client, account.kid, auth_url, nonce, jws_factory
    )
    challenge = authorization.get_challenge_by_type("dns-01")
    domain = authorization.identifier.value

    assert challenge is not None
    assert challenge.is_still_pending()

    key_authorization = solve_dns_challenge(
        authorization.identifier, challenge, jws_factory.jwk, acme_dns
    )

    answers = dns_query("_acme-challenge." + domain)
    assert answers is not None and len(answers) == 1 and answers[0] == key_authorization


@pytest.mark.run(order=3)
def test_dns_challenge_validation_with_response(
    client,
    acme_dns: ACME_DNS,
    identifiers: list[Identifier],
    nonce: Nonce,
    jws_factory: JWSFactory,
):
    account, nonce = create_account(client, URL_ACCOUNT_RESOURCE, nonce, jws_factory)
    orders, nonce = create_order(
        client, URL_NEW_ORDER_RESOURSE, account.kid, nonce, identifiers, jws_factory
    )

    for auth_url in orders.authorizations:
        # auth_url = orders.authorizations[0]
        authorization, nonce = fetch_authorization(
            client, account.kid, auth_url, nonce, jws_factory
        )
        challenge = authorization.get_challenge_by_type("dns-01")

        key_authorization = solve_dns_challenge(
            authorization.identifier, challenge, jws_factory.jwk, acme_dns
        )

        updated_challenge, nonce = respond_to_challenge(
            client, challenge, account.kid, nonce, jws_factory
        )

        authorization_updated, nonce = fetch_authorization(
            client, account.kid, auth_url, nonce, jws_factory
        )

        while authorization_updated.is_still_pending():
            sleep(3)
            authorization_updated, nonce = fetch_authorization(
                client, account.kid, auth_url, nonce, jws_factory
            )

        assert authorization_updated.is_valid()

        updated_challenge = authorization_updated.get_challenge_by_type("dns-01")

        assert updated_challenge.is_valid()

    # After all the challenges are solved, the order should be ready
    updated_order, nonce = check_order(client, orders, account.kid, nonce, jws_factory)
    assert updated_order.is_ready()

    updated_order, nonce = finalize_order(
        client, updated_order, account.kid, nonce, jws_factory
    )

    assert updated_order.is_valid() or updated_order.is_still_processing()

    if updated_order.is_still_processing():
        sleep(updated_order.retry_after)
        updated_order, nonce = check_order(
            client, orders, account.kid, nonce, jws_factory
        )

    # The order should be valid now
    assert updated_order.is_valid()
    assert updated_order.certificate is not None

    cert, nonce = dowload_certificate(
        client, updated_order, account.kid, nonce, jws_factory
    )
    assert is_valid_certificate(cert)

    revoked, nonce = revoke_certificate(
        client, cert, URL_REVOKE_CERTIFICATE_RESOURCE, account.kid, nonce, jws_factory
    )

    assert revoked


# @pytest.mark.skip(reason="Known correct")
def test_challenges_responding(
    client, identifiers: list[Identifier], nonce: Nonce, jws_factory: JWSFactory
):
    account, nonce = create_account(client, URL_ACCOUNT_RESOURCE, nonce, jws_factory)
    orders, nonce = create_order(
        client, URL_NEW_ORDER_RESOURSE, account.kid, nonce, identifiers, jws_factory
    )

    for auth_url in orders.authorizations:
        authorization, nonce = fetch_authorization(
            client, account.kid, auth_url, nonce, jws_factory
        )
        challenge = authorization.get_challenge_by_type("http-01")

        assert challenge is not None
        assert challenge.is_still_pending()

        updated_challenge, nonce = respond_to_challenge(
            client, challenge, account.kid, nonce, jws_factory
        )

        assert updated_challenge.is_still_processing()
        assert updated_challenge.type == challenge.type
        assert updated_challenge.url == challenge.url
        assert updated_challenge.token == challenge.token


@pytest.mark.run(order=3)
def test_http_challenge_validation_with_response(
    client,
    acme_http: ACME_HTTP,
    identifiers: list[Identifier],
    nonce: Nonce,
    jws_factory: JWSFactory,
):
    account, nonce = create_account(client, URL_ACCOUNT_RESOURCE, nonce, jws_factory)
    orders, nonce = create_order(
        client, URL_NEW_ORDER_RESOURSE, account.kid, nonce, identifiers, jws_factory
    )

    for auth_url in orders.authorizations:
        # auth_url = orders.authorizations[0]
        authorization, nonce = fetch_authorization(
            client, account.kid, auth_url, nonce, jws_factory
        )
        # TODO: Cannot verify an wildcard domain with http challenge only dns
        challenge = authorization.get_challenge_by_type("http-01")

        key_authorization = solve_http_challenge(
            authorization.identifier, challenge, jws_factory.jwk, acme_http
        )

        updated_challenge, nonce = respond_to_challenge(
            client, challenge, account.kid, nonce, jws_factory
        )

        authorization_updated, nonce = fetch_authorization(
            client, account.kid, auth_url, nonce, jws_factory
        )

        while authorization_updated.is_still_pending():
            sleep(3)
            authorization_updated, nonce = fetch_authorization(
                client, account.kid, auth_url, nonce, jws_factory
            )

        assert authorization_updated.is_valid()

        updated_challenge = authorization_updated.get_challenge_by_type("http-01")

        assert updated_challenge.is_valid()

        acme_http.remove_key_authorization(updated_challenge.token)

    # After all the challenges are solved, the order should be ready
    updated_order, nonce = check_order(client, orders, account.kid, nonce, jws_factory)
    assert updated_order.is_ready()

    updated_order, nonce = finalize_order(
        client, updated_order, account.kid, nonce, jws_factory
    )

    assert updated_order.is_valid() or updated_order.is_still_processing()

    if updated_order.is_still_processing():
        sleep(updated_order.retry_after)
        updated_order, nonce = check_order(
            client, orders, account.kid, nonce, jws_factory
        )

    # The order should be valid now
    assert updated_order.is_valid()
    assert updated_order.certificate is not None

    cert, nonce = dowload_certificate(
        client, updated_order, account.kid, nonce, jws_factory
    )
    assert is_valid_certificate(cert)

    revoked, nonce = revoke_certificate(
        client, cert, URL_REVOKE_CERTIFICATE_RESOURCE, account.kid, nonce, jws_factory
    )

    assert revoked
