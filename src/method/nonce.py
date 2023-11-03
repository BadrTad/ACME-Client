import httpx
from acme_types import Nonce, URL


def get_nonce(client: httpx.Client, urlNonce: URL) -> Nonce:
    """Gets a nonce from the ACME server

    Returns:
        Nonce: Nonce from the ACME server
    """
    response = client.head(urlNonce)
    if response.is_error:
        raise Exception("Error getting nonce: " + response.text)

    nonce = response.headers["Replay-Nonce"]
    return nonce
