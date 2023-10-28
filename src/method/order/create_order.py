import httpx
import acme_debug

from jws.jws import JWSFactory

from acme_types import URL, Nonce, Dict, Tuple
from method.acme_objects import Identifier, Orders


def create_order(
    urlOrder: URL,
    kid: str,
    nonce: Nonce,
    identifiers: list[Identifier],
    factory: JWSFactory,
) -> Tuple[Orders, Nonce]:
    """Creates an order with the given identifiers."""
    jws_header_params = {"url": urlOrder, "nonce": nonce, "kid": kid}
    jws_payload = {"identifiers": [identifier.as_json() for identifier in identifiers]}
    jws = factory.build_JWS_with_kid(jws_header_params, jws_payload)

    headers = {
        "Content-Type": "application/jose+json",
        "Accept": "application/json",
    }

    response = httpx.post(
        urlOrder, headers=headers, json=jws, verify=False, proxies=acme_debug.PROXIES
    )

    if response.is_error:
        raise Exception("Error creating order", response.json)

    order_url = response.headers["Location"]  # This order url location
    new_nonce = response.headers["Replay-Nonce"]

    orders = Orders(response.json(), order_url)
    return orders, new_nonce
