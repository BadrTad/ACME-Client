import httpx
from acme_types import Nonce, URL

import acme_debug


def get_nonce(urlNonce: URL) -> Nonce:
    """Gets a nonce from the ACME server

    Returns:
        Nonce: Nonce from the ACME server
    """
    response = httpx.head(urlNonce, verify=False, proxies=acme_debug.PROXIES)
    if response.is_error:
        raise Exception("Error getting nonce: " + response.text)

    nonce = response.headers["Replay-Nonce"]
    return nonce
