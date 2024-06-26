import httpx

from method.acme_objects import Account
from acme_types import URL, Json, Nonce, Tuple
from jws.jws import JWSFactory


def create_account(
    client: httpx.Client, newAccountEndpoint: URL, nonce: Nonce, factory: JWSFactory
) -> Tuple[Account, Nonce]:
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
    account, new_nonce = send_post_request_for_account(client, newAccountEndpoint, jws)
    return account, new_nonce


def send_post_request_for_account(
    client: httpx.Client, url: URL, jws: Json
) -> Tuple[Account, Nonce]:
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
    response = client.post(
        url,
        headers=headers,
        json=jws,
    )
    if response.is_error:
        raise Exception("Error creating account", response.json())

    kid = response.headers["Location"]
    account = Account(response.json(), kid)
    new_nonce = response.headers["Replay-Nonce"]
    return account, new_nonce


def format_jws(payload: Json, url, nonce, factory: JWSFactory) -> Json:
    """Formats a JWS for the POST request to the ACME server

    Returns:
        Json: JWS
    """
    jws_header_params = {"url": url, "nonce": nonce}
    return factory.build_JWS_with_jwk(jws_header_params, payload)
