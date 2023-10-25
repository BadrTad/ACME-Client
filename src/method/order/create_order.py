import httpx
from acme_types import URL, Nonce, Dict, Tuple
from method.acme_objects import Orders
from util.jws.jws import  JWSFactory

import acme_debug, pprint


def create_order(urlOrder: URL, kid: str, nonce: Nonce, identifiers: list[Dict[str,str]], factory: JWSFactory) -> Tuple[Orders, Nonce]:
    """Creates an order with the given identifiers."""
    jws_header_params = {"url": urlOrder, "nonce": nonce, "kid": kid}
    jws_payload = {"identifiers": identifiers}
    jws = factory.build_JWS_with_kid(jws_header_params, jws_payload)

    headers = {
        "Content-Type": "application/jose+json",
        "Accept": "application/json",
    }
    
    response = httpx.post(urlOrder, headers=headers, json=jws, verify=False, proxies=acme_debug.PROXIES)

    if response.is_error:
        pprint(response.json)
        raise Exception("Error creating order")

    
    order_url = response.headers['Location'] # This order url location
    new_nonce = response.headers['Replay-Nonce']
    
    orders = Orders(response.json())
    orders.set_order_url(order_url)
    return orders, new_nonce



if __name__ == "__main__":
    from pprint import pprint
    from acme_debug import URL_ACCOUNT_RESOURCE, URL_NONCE_RESOURCE, URL_NEW_ORDER_RESOURSE
    from method.nonce import get_nonce
    from method.account.create_account import create_account
   
    jws_factory = acme_debug.get_debug_jws_factory()

    nonce = get_nonce(URL_NONCE_RESOURCE)
    account, nonce = create_account(URL_ACCOUNT_RESOURCE, nonce, jws_factory)

    kid = account.get_kid()

    identifiers = [{"type": "dns", "value": "example.com"}, {"type": "dns", "value": "www.example.com"}]
    orders, nonce = create_order(URL_NEW_ORDER_RESOURSE, kid, nonce, identifiers, jws_factory)

    print(orders)
    
    
    