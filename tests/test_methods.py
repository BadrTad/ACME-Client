import pytest

from jws.jws import JWSFactory

from method.directory.fetch_directory import fetch_directory
from method.nonce import get_nonce
from method.account.create_account import create_account
from method.order.create_order import create_order

from acme_debug import URL_ACME_DIR, URL_ACCOUNT_RESOURCE, URL_NEW_ORDER_RESOURSE, URL_NONCE_RESOURCE, get_debug_jws_factory
from validation import *

@pytest.fixture(autouse=True)
def jws_factory() -> JWSFactory:
    return get_debug_jws_factory(new=False)

@pytest.fixture()
def nonce() -> str:
    nonce = get_nonce(URL_NONCE_RESOURCE)
    if not is_valid_nonce(nonce):
        raise Exception("Error getting valid nonce")
    return nonce
    
    
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
        assert is_valid_kid(account.kid)
        account.contact is list
        len(account.contact) > 0

        assert is_valid_nonce(new_nonce)

    except Exception as e:
        print(e)
        assert False

def test_order_creation(nonce: str, jws_factory: JWSFactory):
    #First we create an order 
    account, nonce = create_account(URL_ACCOUNT_RESOURCE, nonce, jws_factory)

    # Select the identifiers we want to order for
    identifiers = [{"type": "dns", "value": "example.com"}, {"type": "dns", "value": "www.example.com"}]

    try:
        orders, new_nonce = create_order(URL_NEW_ORDER_RESOURSE, account.kid, nonce, identifiers, jws_factory)
        assert orders.status == "pending"
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
    
    

    