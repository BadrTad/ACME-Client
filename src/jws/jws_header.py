from jws.jwk import JWKey, JWKeyEncoder
from acme_types import Nonce, Optional
import copy, json

class JWSHeader():
    """Flattened JWS header implementation."""

    def __init__(self,url: str, nonce: Nonce, alg: str = "ES256", kid: str = None, jwk: JWKey = None) -> None:
        self.alg = alg
        self.url = url
        self.nonce = nonce
        if kid is not None:
            self.kid: Optional[str] = kid
        if jwk is not None:
            self.jwk: Optional[JWKey] = jwk


class JWSHeaderEncoder(json.JSONEncoder):
    """JSON encoder for JWSHeader objects."""

    def default(self, obj):
        if isinstance(obj, JWSHeader):
            d = copy.copy(obj.__dict__)
            if 'jwk' in obj.__dict__:
                jwk = JWKeyEncoder.default(self,obj.jwk)
                d['jwk'] = jwk
                return d

            assert 'kid' in obj.__dict__
            return d    
