URL_ACCOUNT_RESOURCE = "https://172.30.210.4:14000/sign-me-up"
URL_NONCE_RESOURCE = "https://172.30.210.4:14000/nonce-plz"
URL_NEW_ORDER_RESOURSE = "https://172.30.210.4:14000/order-plz"
URL_REVOKE_CERTIFICATE_RESOURCE = "https://172.30.210.4:14000/revoke-cert"


URL_ACME_DIR = "https://172.30.210.4:14000/dir"

PROXIES = {
    "http://": "http://172.30.208.1:8080",
    "https://": "http://172.30.208.1:8080",
}

from jws.jws import JWSFactory
from util.crypto import generate_keypair, load_keypair, save_keypair

def new_keypair(save_to_file= True) :
    sk, vk  = generate_keypair()
    if save_to_file:
       save_keypair('debug/', sk, vk)

    return sk, vk

JWS_FACTORY = None

def get_debug_jws_factory(new=False) -> JWSFactory:
    """Returns a JWSFactory for debugging purposes."""
    global JWS_FACTORY
    if JWS_FACTORY is None:
        if new:
            sk, vk = new_keypair()
        else:
            sk, vk = load_keypair("debug/sk.pem", "debug/vk.pem")
        JWS_FACTORY = JWSFactory(sk, vk)
    return JWS_FACTORY


