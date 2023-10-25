import json
import copy 

from jws.jwk import JWKey, JWKeyEncoder
from acme_types import Nonce, Optional

class JWSHeader():
    """Flattened JWS header implementation."""
    alg: str
    url: str
    nonce: Nonce
    jwk: Optional[JWKey]
    kid: Optional[str]
    crv: Optional[str]

    def __init__(self, alg: str, url: str, nonce: Nonce) -> None:
        self.alg = alg
        self.url = url
        self.nonce = nonce

    def with_kid(url: str, nonce: Nonce, kid: str, alg="ES256") -> 'JWSHeader':
        """Sets the kid field of the JWSHeader."""
        self = JWSHeader(alg, url, nonce)
        self.kid = kid
        return self

    def with_jwk(url: str, nonce: Nonce,  jwk: JWKey, alg: str = "ES256") -> 'JWSHeader':
        """Sets the jwk field of the JWSHeader."""
        self = JWSHeader(alg, url, nonce)
        self.jwk = jwk
        return self

class JWSHeaderEncoder(json.JSONEncoder):
    """JSON encoder for JWSHeader objects."""

    def default(self, obj):
        if isinstance(obj, JWSHeader):
            # obj.nonce = url64.encode(obj.nonce)
            d = copy.copy(obj.__dict__)
            if 'jwk' in obj.__dict__:
                jwk = JWKeyEncoder.default(self,obj.jwk)
                d['jwk'] = jwk
                return d

            assert 'kid' in obj.__dict__
            return d    


        return json.JSONEncoder.default(self, obj)
