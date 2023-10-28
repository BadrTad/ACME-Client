import base64
import url64

from jws.jws import JWSFactory
from acme_types import Json
import acme_debug
from validation import is_valid_signature
import pytest


@pytest.fixture
def crypto_keys():
    sk, vk = acme_debug.load_keypair("debug/sk.pem", "debug/vk.pem")
    return sk, vk


@pytest.fixture
def kid_header() -> Json:
    return {
        "url": "https://some_utl.com/1234",
        "nonce": "1234",
        "kid": "account_id_1234",
    }


@pytest.fixture
def jwk_header() -> Json:
    return {"url": "https://some_utl.com/1234", "nonce": "1234"}


@pytest.fixture
def jws_payload() -> Json:
    return {"key1": "value2", "key2": ["value2", "value3"], "key3": {"key4": "value4"}}


def base64url_decode(payload):
    size = len(payload) % 4
    if size == 2:
        payload += "=="
    elif size == 3:
        payload += "="
    elif size != 0:
        raise ValueError("Invalid base64 string")
    return base64.urlsafe_b64decode(payload.encode("utf-8"))


def test_jws_factory_build_JWS_with_kid(
    crypto_keys, kid_header: Json, jws_payload: Json
):
    jws_factory = JWSFactory(*crypto_keys)

    jws = jws_factory.build_JWS_with_kid(kid_header, jws_payload)

    assert "protected" in jws
    assert "payload" in jws
    assert "signature" in jws

    assert jws["payload"] == url64.encode(jws_payload)
    assert is_valid_signature(jws["signature"], base64url_decode)


def test_jws_factory_build_JWS_with_kid_with_empty_payload(
    crypto_keys, kid_header: Json
):
    jws_factory = JWSFactory(*crypto_keys)

    jws = jws_factory.build_JWS_with_kid(kid_header, jws_payload="")
    jws_empty_json = jws_factory.build_JWS_with_kid(kid_header, jws_payload={})

    assert "protected" in jws and "protected" in jws_empty_json
    assert "payload" in jws and "payload" in jws_empty_json
    assert "signature" in jws and "signature" in jws_empty_json

    assert jws["payload"] == "" and jws_empty_json["payload"] == url64.encode({})
    assert is_valid_signature(jws["signature"], base64url_decode)


def test_jws_factory_build_JWS_with_jwk(
    crypto_keys, jwk_header: Json, jws_payload: Json
):
    jws_factory = JWSFactory(*crypto_keys)

    jws = jws_factory.build_JWS_with_jwk(jwk_header, jws_payload)
    jws_empty_json = jws_factory.build_JWS_with_jwk(jwk_header, jws_payload)

    assert "protected" in jws and "protected" in jws_empty_json
    assert "payload" in jws and "payload" in jws_empty_json
    assert "signature" in jws and "signature" in jws_empty_json

    assert jws["payload"] == url64.encode(jws_payload)
    assert is_valid_signature(jws["signature"], base64url_decode)


def test_jws_factory_build_JWS_with_jwk_with_empty_payload(
    crypto_keys, jwk_header: Json
):
    jws_factory = JWSFactory(*crypto_keys)

    jws = jws_factory.build_JWS_with_jwk(jwk_header, jws_payload="")
    jws_empty_json = jws_factory.build_JWS_with_jwk(jwk_header, jws_payload={})

    assert "protected" in jws and "protected" in jws_empty_json
    assert "payload" in jws and "payload" in jws_empty_json
    assert "signature" in jws and "signature" in jws_empty_json
    assert is_valid_signature(jws["signature"], base64url_decode)
