import httpx
import url64
import os

import acme_debug
from acme_types import URL, Optional, Tuple, Nonce

from jws.jws import JWSFactory

from method.acme_objects import Order
from util.certificate import get_der_cert_for_pem


def dowload_certificate(
    order: Order,
    kid: str,
    nonce: str,
    jws_factory: JWSFactory,
    save_file: Optional[str] = "debug/acmecert.PEM",
) -> Tuple[str, Nonce]:
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

    return cert_bytes.decode(), new_nonce


def revoke_certificate(
    pem_cert: str | bytes,
    revocation_url: URL,
    kid: str,
    nonce: Nonce,
    jws_factory: JWSFactory,
) -> Tuple[bool, Nonce]:
    """Revokes the certificate."""

    def _get_pem_cert_bytes_from_arg(pem_cert: str) -> bytes:
        if isinstance(pem_cert, str):
            if os.path.isfile(pem_cert):
                with open(pem_cert, "rb") as f:
                    return f.read()
            else:
                return pem_cert.encode("utf-8")
        else:
            return pem_cert

    pem_cert_bytes = _get_pem_cert_bytes_from_arg(pem_cert)

    cert_der = get_der_cert_for_pem(pem_cert_bytes)
    cert_der = url64.encode(cert_der)

    jws_header_params = {"url": revocation_url, "kid": kid, "nonce": nonce}
    jws_payload = {"certificate": cert_der, "reason": 0}

    jws = jws_factory.build_JWS_with_kid(jws_header_params, jws_payload)

    headers = {"Content-Type": "application/jose+json"}

    response = httpx.post(
        revocation_url,
        headers=headers,
        json=jws,
        verify=False,
        proxies=acme_debug.PROXIES,
    )

    new_nonce = response.headers["Replay-Nonce"]

    if response.is_error:
        print("Error revoking certificate", response.json())

    return response.is_success, new_nonce
