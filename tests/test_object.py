from acme_types import URL, Json
from method.acme_objects import Account, Authorization, Challenge, Identifier, Orders
import json


def test_account_object():
    data = """
    {
        "status": "valid",
        "contact": [
            "mailto:cert-admin@example.org",
            "mailto:admin@example.org"
        ],
        "termsOfServiceAgreed": true,
        "orders": "https://example.com/acme/orders/rzGoeA"
    }
    """
    j = json.loads(data)    
    account = Account(j, kid= "kid")
    assert account.status == "valid"
    assert account.contact == [ "mailto:cert-admin@example.org","mailto:admin@example.org"]
    assert account.termsOfServiceAgreed == True
    assert account.orders == "https://example.com/acme/orders/rzGoeA"
    assert account.kid == "kid"


def test_orders_object():
    data = """
    {
        "status": "pending",
        "expires": "2023-10-26T12:58:57Z",
        "identifiers": [
            {
                "type": "dns",
                "value": "www.example.com"
            },
            {
                "type": "dns",
                "value": "example.com"
            }
        ],
        "finalize": "https://localhost:14000/finalize-order/uL2DgNiH9MGu7cQJYBMDKVKLwtFpV0TNh5tZqq16AJg",
        "authorizations": [
            "https://localhost:14000/authZ/Ufi9M3Mc0NcDVtguAK_ZH6lLVr7Bet7-j-0B6LS5ozY",
            "https://localhost:14000/authZ/W_9V90Ezz9iiVM-KCPiaxnVQRbGnlefR33LW4tOpnYg"
        ]
    }
    """
    j = json.loads(data)
    orders = Orders(j, "order/url")
    assert orders.status == "pending"
    assert orders.expires == "2023-10-26T12:58:57Z"
    assert orders.identifiers[0].type == "dns"
    assert orders.identifiers[0].value == "www.example.com"
    assert orders.identifiers[1].type == "dns"
    assert orders.identifiers[1].value == "example.com"
    assert orders.finalize == "https://localhost:14000/finalize-order/uL2DgNiH9MGu7cQJYBMDKVKLwtFpV0TNh5tZqq16AJg"
    assert orders.authorizations[0] == "https://localhost:14000/authZ/Ufi9M3Mc0NcDVtguAK_ZH6lLVr7Bet7-j-0B6LS5ozY"
    assert orders.authorizations[1] == "https://localhost:14000/authZ/W_9V90Ezz9iiVM-KCPiaxnVQRbGnlefR33LW4tOpnYg"
    


def test_authorization_object():
    data = """
    {
        "status": "pending",
        "expires": "2016-01-02T14:09:30Z",

        "identifier": {
        "type": "dns",
        "value": "www.example.org"
        },

        "challenges": [
        {
            "type": "http-01",
            "url": "https://example.com/acme/chall/prV_B7yEyA4",
            "token": "DGyRejmCefe7v4NfDGDKfA"
        },
        {
            "type": "dns-01",
            "url": "https://example.com/acme/chall/Rg5dV14Gh1Q",
            "token": "DGyRejmCefe7v4NfDGDKfA"
        }
        ]
    }
    """
    j = json.loads(data)
    auth = Authorization(j, "auth/url")
    assert auth.status == "pending"
    assert auth.expires == "2016-01-02T14:09:30Z"
    assert auth.identifier.type == "dns"
    assert auth.identifier.value == "www.example.org"
    assert auth.challenges[0].type == "http-01"
    assert auth.challenges[0].url == "https://example.com/acme/chall/prV_B7yEyA4"
    assert auth.challenges[0].token == "DGyRejmCefe7v4NfDGDKfA"
    assert auth.challenges[1].type == "dns-01"
    assert auth.challenges[1].url == "https://example.com/acme/chall/Rg5dV14Gh1Q"
    assert auth.challenges[1].token == "DGyRejmCefe7v4NfDGDKfA"
    assert auth.auth_url == "auth/url"
    