
from acme_debug import URL_ACME_DIR, URL_ACCOUNT_RESOURCE, URL_NONCE_RESOURCE, get_debug_jws_factory
from jws.jws import JWSFactory
from method.account.create_account import create_account
from method.directory.fetch_directory import fetch_directory
from method.nonce import get_nonce

import re
import pytest

@pytest.fixture(autouse=True)
def jws_factory() -> JWSFactory:
    return get_debug_jws_factory()

@pytest.fixture()
def nonce() -> str:
    nonce = get_nonce(URL_NONCE_RESOURCE)
    if not is_valid_nonce(nonce):
        raise Exception("Error getting valid nonce")
    return nonce
    

def is_json_error(j: dict):
    return 'status' in j and j['status'] is int and j['status'] >= 400


def is_valid_nonce(s: str):
    # Check if the string contains only valid Base64 URL characters.
    return s and re.match(r'^[A-Za-z0-9_-]*$', s)

def test_directory():
    try:
        j = fetch_directory(URL_ACME_DIR)
        assert not is_json_error(j)
    except Exception as e:
        print(e)
        assert False

def test_nonce():
    try:
        nonce = get_nonce(URL_NONCE_RESOURCE)
        assert is_valid_nonce(nonce)
        assert len(nonce) > 0
    except Exception as e:
        print(e)
        assert False


def test_account_creation(nonce: str, jws_factory: JWSFactory):
    try:
        account, new_nonce = create_account(URL_ACCOUNT_RESOURCE, nonce, jws_factory)
        account.status == "valid"
        account.get_kid() is str
        assert len(account.kid) > 0
        account.contact is list
        len(account.contact) > 0

        assert is_valid_nonce(new_nonce)

    except Exception as e:
        print(e)
        assert False

    