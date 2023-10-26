import re
from datetime import datetime
from typing import Callable

from method.acme_objects import Challenge, Identifier
from acme_types import URL, Nonce

def is_valid_signature(signature: str, deocoder: Callable[[str], bytes], signature_size_bytes = 64) -> bool:
    base64_url_pattern = r'^[A-Za-z0-9_-]*$'
    is_base_64_url = bool(signature) and bool(re.match(base64_url_pattern, signature))
    
    try:
        signature_bytes = deocoder(signature)
    except ValueError:
        return False
    
    return is_base_64_url and len(signature_bytes) == signature_size_bytes

def is_json_error(j: dict) -> bool:
    return 'status' in j and j['status'] is int and j['status'] >= 400

def is_valid_nonce(nonce: Nonce) -> bool:
    # Check if the string contains only valid Base64 URL characters.
    return bool(nonce) and bool(re.match(r'^[A-Za-z0-9_-]*$', nonce))

def is_valid_kid(kid: str) -> bool:
    reg_kid_pattern = r'^https:\/\/(\d+\.\d+\.\d+\.\d+):(\d+)\/my-account\/([0-9a-fA-F]+)$'
    return bool(kid) and bool(re.match(reg_kid_pattern, kid))

def are_valid_identifiers(requested_identifiers:list[Identifier],
                          received_identifiers: list[Identifier]):

    rqs_s = sorted(received_identifiers, key=lambda i: i.value)
    rcv_s = sorted(requested_identifiers, key=lambda i: i.value)
    pairs = zip(rqs_s, rcv_s)
    return all( rqs == rcs for rqs ,rcs in pairs)
    
def is_valid_finalize(finalize: URL) -> bool:
    reg_finalize_pattern = r'^https:\/\/(\d+\.\d+\.\d+\.\d+):(\d+)\/finalize-order\/([0-9a-zA-Z_-]+)$'
    return bool(finalize) and bool(re.match(reg_finalize_pattern, finalize))

def are_valid_authorizations(authorizations: list[str]) -> bool:
    def is_valid_authorization(authorization: str)-> bool:
        url_pattern = r'^https:\/\/(\d+\.\d+\.\d+\.\d+):(\d+)\/authZ\/([0-9a-zA-Z_-]+)$'
        return bool(authorization) and bool(re.match(url_pattern, authorization))

    return bool(authorizations) and all(map(is_valid_authorization, authorizations))

def is_valid_expires(expires: str) -> bool:
    try:
       # Parse the date string into a datetime object.
        _ = datetime.strptime(expires, "%Y-%m-%dT%H:%M:%SZ")
        return True
    
    except ValueError:
        return False
    
def is_valid_order_url(order_url: URL) -> bool:
    reg_order_url_pattern = r'^https:\/\/(\d+\.\d+\.\d+\.\d+):(\d+)\/my-order\/([0-9a-zA-Z_-]+)$'
    return bool(order_url) and bool(re.match(reg_order_url_pattern, order_url))


def are_valid_challenges(challenges: list[Challenge]) -> bool:
  
    def is_valid_challenge_url(url: URL) -> bool:
        reg_challenge_url_pattern = r'^https:\/\/(\d+\.\d+\.\d+\.\d+):(\d+)\/chalZ\/([0-9a-zA-Z_-]+)$'
        return bool(url) and bool(re.match(reg_challenge_url_pattern, url))

    def is_valid_challenge_token(token: str) -> bool:
        return bool(token) and bool(re.match(r'^[A-Za-z0-9_-]*$', token))

    def is_valid_challenge_type(challenge_type: str) -> bool:
        return challenge_type in ["http-01", "dns-01", "tls-alpn-01"]

    def is_valid_challenge(challenge: Challenge) -> bool:
        return is_valid_challenge_type(challenge.type) \
            and is_valid_challenge_url(challenge.url) \
            and is_valid_challenge_token(challenge.token)

    return bool(challenges) and all(map(is_valid_challenge, challenges))
    

if __name__ == "__main__":
    # test are_valid_identifiers
    requested_identifiers = [{"type": "dns", "value": "example.com"}, {"type": "dns", "value": "www.example.com"}]
    received_identifiers  = [{"type": "dns", "value": "www.example.com"}, {"type": "dns", "value": "example.com"}]
    assert are_valid_identifiers(requested_identifiers, received_identifiers)


    expires = '2023-10-25T18:43:14Z' 
    assert is_valid_expires(expires)
    