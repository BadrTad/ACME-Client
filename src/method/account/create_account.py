import httpx
from pprint import pprint
import acme_debug

from method.acme_objects import Account
from acme_types import URL, Json, Nonce, Tuple
from util.jws import JWSFactory


def create_account(newAccountEndpoint: URL, nonce: Nonce, factory: JWSFactory) -> Tuple[Account, Nonce]:
    """Creates a new account by sending a POST request to the ACME server

    Args:
        newAccountEndpoint (URL): ACME endpoint resource for creating a new account
        nonce (Nonce): Nonce from the ACME server

    Returns:
        Account: created account object 
        Nonce: new nonce
    
    """
    payload = {
        "termsOfServiceAgreed": True,
        "contact": ["mailto:badrtad@gmail.com"],
        "onlyReturnExisting": False,
        # "externalAccountBinding": {...}
    }

    jws = format_jws(payload, newAccountEndpoint, nonce, factory)
    account, new_nonce, kid = send_post_request_for_account(newAccountEndpoint, jws)
    account.set_kid(kid)
    return account, new_nonce


def send_post_request_for_account(url: URL, jws: Json) -> Tuple[Account, Nonce, str]:
    """Formats a POST request to the ACME server

    Returns:
        Account: Account object
        Nonce: new nonce
        kid: kid of the account
    """
    headers = {
        "Content-Type": "application/jose+json",
        "Accept": "application/json",

    }
    response = httpx.post(url, headers=headers, json=jws, verify=False, proxies=acme_debug.PROXIES)
    if response.is_error:
        pprint(response.json())
        raise Exception("Error creating account")

        
    return Account(response.json()), response.headers['Replay-Nonce'], response.headers['Location']
    


def format_jws(payload:Json, url, nonce, factory: JWSFactory) -> Json:
    """Formats a JWS for the POST request to the ACME server

    Returns:
        Json: JWS
    """
    jws_header_params = {"url": url, "nonce": nonce}
    return factory.build_JWS_with_jwk(jws_header_params, payload)




if __name__ == '__main__':
    from method.nonce import get_nonce
    from acme_debug import URL_ACCOUNT_RESOURCE, URL_NONCE_RESOURCE

    jws_factory = acme_debug.get_debug_jws_factory()

    nonce = get_nonce(URL_NONCE_RESOURCE)
    create_account(URL_ACCOUNT_RESOURCE, nonce, jws_factory)
