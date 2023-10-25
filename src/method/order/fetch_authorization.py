import pprint
import httpx

from jws.jws import JWSFactory
from method.acme_objects import Authorization
from acme_types import URL, Nonce, Tuple
import acme_debug


def fetch_challenges_for_authorization(
    account_id: str,
    authorization_url: URL,
    nonce: Nonce,
    jws_factory: JWSFactory
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
        jws_header_params={"url": authorization_url, "nonce": nonce, 'kid': account_id},
        jws_payload={}
    )

    headers = {
        "Content-Type": "application/jose+json",
        "Accept": "application/json",
    }

    response = httpx.post(authorization_url,
                          headers=headers,
                          json=jws,
                          verify=False,
                          proxies=acme_debug.PROXIES)

    if response.is_error:
        raise Exception("Error fetching challenge for authorization", response.json)

    pprint.pprint(response.json())
    authorization = Authorization(response.json(), authorization_url)
    new_nonce = response.headers['Replay-Nonce']
    print(authorization)

    return authorization, new_nonce
