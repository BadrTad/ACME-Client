import httpx
import hashlib
import url64
from acme_http import ACME_HTTP
from jws.jwk import JWKey

from jws.jws import JWSFactory
from method.acme_objects import Authorization, Challenge, Identifier
from acme_types import URL, KeyAuthorizaton, Nonce, Tuple

from acme_dns import ACME_DNS


def fetch_authorization(
    client: httpx.Client,
    account_id: str,
    authorization_url: URL,
    nonce: Nonce,
    jws_factory: JWSFactory,
) -> Tuple[Authorization, Nonce]:
    """Fetch Authorization object containing the challenges for the given authorization url.

    Args:
        account_id (str): id of the account
        authorization_url (URL): url of the authorization
        nonce (Nonce): nonce
        jws_factory (JWSFactory): jws factory

    Raises:
        Exception: raised if ACME responds with an error

    Returns:
        Tuple[Authorization, Nonce]: Authorization object and a new nonce
    """

    jws = jws_factory.build_JWS_with_kid(
        jws_header_params={"url": authorization_url, "nonce": nonce, "kid": account_id},
        jws_payload="",
    )

    headers = {
        "Content-Type": "application/jose+json",
        "Accept": "application/json",
    }

    response = client.post(
        authorization_url,
        headers=headers,
        json=jws,
    )

    if response.is_error:
        raise Exception("Error fetching challenge for authorization", response.json)

    authorization = Authorization(response.json(), authorization_url)
    new_nonce = response.headers["Replay-Nonce"]

    return authorization, new_nonce


def get_key_authorization_from(token: str, thumbprint: str, hashed=True) -> str:
    key_authorization = f"{token}.{thumbprint}"
    if hashed:
        hashed_key = hashlib.sha256(key_authorization.encode("utf-8")).digest()
        return url64.encode(hashed_key)
    else:
        return key_authorization


def solve_dns_challenge(
    identifier: Identifier, challenge: Challenge, jwk: JWKey, acme_dns: ACME_DNS
) -> KeyAuthorizaton:
    """Solves the dns challenge by adding a TXT record of the key authorization to the ACME DNS server.

    Args:
        identifier (Identifier): the domain identifier
        challenge (Challenge): the challenge object of type dns-01
        jwk (JWKey): account key
        acme_dns (ACME_DNS): ACME DNS server to be used
    """

    token = challenge.token
    thumbprint = jwk.thumbprint()

    key_authorization = get_key_authorization_from(token, thumbprint)
    domain = identifier.value

    acme_dns.serve_record(domain, "TXT", key_authorization)

    return key_authorization


def solve_http_challenge(
    identifier: Identifier, challenge: Challenge, jwk: JWKey, acme_http: ACME_HTTP
) -> KeyAuthorizaton:
    token = challenge.token
    thumbprint = jwk.thumbprint()

    key_authorization = get_key_authorization_from(token, thumbprint, hashed=False)

    acme_http.serve_key_authorization(token, key_authorization)

    return key_authorization


def respond_to_challenge(
    client: httpx.Client,
    challenge: Challenge,
    account_id: URL,
    nonce: Nonce,
    jws_factory: JWSFactory,
) -> Tuple[Challenge, Nonce]:
    """Respond to the challenge.

    Args:
        challenge (Challenge): challenge to respond to
        nonce (Nonce): nonce
        jws_factory (JWSFactory): jws factory

    Raises:
        Exception: raised if ACME responds with an error

    Returns:
        Tuple[Challenge, Nonce]: Challenge object and a new nonce
    """

    jws = jws_factory.build_JWS_with_kid(
        jws_header_params={"url": challenge.url, "nonce": nonce, "kid": account_id},
        jws_payload={},
    )

    headers = {
        "Content-Type": "application/jose+json",
        "Accept": "application/json",
    }

    response = client.post(
        challenge.url,
        headers=headers,
        json=jws,
    )

    if response.is_error:
        raise Exception("Error responding to challenge", response.json)

    updated_challenge = Challenge(response.json())
    new_nonce = response.headers["Replay-Nonce"]

    return updated_challenge, new_nonce
