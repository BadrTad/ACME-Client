from typing import Optional
import httpx
import acme_debug

from jws.jws import JWSFactory

from acme_types import URL, Nonce, Dict, Tuple
from method.acme_objects import Identifier, Order
from util.csr import create_csr


def create_order(
    urlOrder: URL,
    kid: str,
    nonce: Nonce,
    identifiers: list[Identifier],
    factory: JWSFactory,
) -> Tuple[Order, Nonce]:
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

    orders = Order(response.json(), order_url)
    return orders, new_nonce


def check_order(
    order: Order, kid: str, nonce: Nonce, factory: JWSFactory
) -> Tuple[Order, Nonce]:
    """Checks the status of the order."""
    jws_header_params = {"url": order.order_url, "nonce": nonce, "kid": kid}
    jws_payload = ""
    jws = factory.build_JWS_with_kid(jws_header_params, jws_payload)

    headers = {
        "Content-Type": "application/jose+json",
        "Accept": "application/json",
    }

    response = httpx.post(
        order.order_url,
        headers=headers,
        json=jws,
        verify=False,
        proxies=acme_debug.PROXIES,
    )

    if response.is_error:
        raise Exception("Error checking order", response.json())

    new_nonce = response.headers["Replay-Nonce"]

    return Order(response.json(), order.order_url), new_nonce


def finalize_order(
    order: Order, kid: str, nonce: Nonce, jwk_factory: JWSFactory
) -> Tuple[Order, Nonce]:
    jws_header_params = {"url": order.finalize, "nonce": nonce, "kid": kid}

    csr = create_csr(order.identifiers)
    jws_payload = {"csr": csr}

    jws = jwk_factory.build_JWS_with_kid(jws_header_params, jws_payload=jws_payload)

    headers = {
        "Content-Type": "application/jose+json",
        "Accept": "application/json",
    }

    response = httpx.post(
        order.finalize,
        headers=headers,
        json=jws,
        verify=False,
        proxies=acme_debug.PROXIES,
    )
    if response.is_error:
        raise Exception("Error finalizing order", response.json())

    new_nonce = response.headers["Replay-Nonce"]

    updated_order = Order(response.json(), order.order_url)

    # If the order is still processing, we need to wait for the Retry-After time
    # This information gets added to the order object
    if updated_order.status == "processing":
        retry_after = response.headers["Retry-After"]
        updated_order.add_retry_after(retry_after)

    return updated_order, new_nonce


def dowload_certificate(
    order: Order,
    kid: str,
    nonce: str,
    jws_factory: JWSFactory,
    save_file: Optional[str] = "debug/acmecert.PEM",
) -> Tuple[bytes, Nonce]:
    """Downloads the certificate from the order."""
    jws_header_params = {"url": order.certificate, "kid": kid, "nonce": nonce}
    jws_payload = ""
    jws = jws_factory.build_JWS_with_kid(jws_header_params, jws_payload)

    headers = {
        "Content-Type": "application/jose+json",
        "Accept": "application/pem-certificate-chain",
    }

    response = httpx.post(
        order.certificate,
        headers=headers,
        json=jws,
        verify=False,
        proxies=acme_debug.PROXIES,
    )

    cert_bytes = response.content
    new_nonce = response.headers["Replay-Nonce"]

    if response.is_error:
        raise Exception("Error downloading certificate", response.json())

    if save_file is not None:
        with open(save_file, "wb") as f:
            f.write(cert_bytes)

    return cert_bytes.decode("utf-8"), new_nonce
