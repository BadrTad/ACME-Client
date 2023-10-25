import json, url64, copy
from util.crypto import SigningKey, VerifyingKey
from acme_types import Json , Signature, Tuple

from jws.jwk import JWKey
from jws.jws_header import JWSHeader, JWSHeaderEncoder



class JWSFactory():
    """Factory for creating JWS objects."""
    _signing_key: SigningKey
    verifying_key: VerifyingKey

    def __init__(self, signing_key: SigningKey, verifying_key: VerifyingKey):
        self._signing_key = signing_key
        self.verifying_key = verifying_key

    def _signature_for(self, jws_header: Json, jws_payload: Json) -> Signature:
        """Computes the signature for a JWS object."""

        jws_header = url64.encode(jws_header)
        jws_payload = url64.encode(jws_payload)
        s_bytes = self._signing_key.sign(
            (jws_header + "." + jws_payload).encode("utf-8"))

        return s_bytes

    def _get_public_key_point(self) -> Tuple[int, int]:
        """Returns the public key as EC point."""
        x = self.verifying_key.pubkey.point.x()
        y = self.verifying_key.pubkey.point.y()
        return x, y

    def build_JWS_with_jwk(self,jws_header_params: Json, jws_payload: Json) -> Json:
        """Builds a JWS object."""
        x, y = self._get_public_key_point()
        jwk = JWKey(x, y)
        
        jws_header = JWSHeader.with_jwk(**jws_header_params, jwk=jwk)
        jws = self.parse_with_signature_JWS(jws_header, jws_payload)
        
        return jws.as_json()

    def build_JWS_with_kid(self, jws_header_params: Json, jws_payload: Json) -> Json:
        """Builds a JWS object."""
        jws_header = JWSHeader.with_kid(**jws_header_params)
        jws = self.parse_with_signature_JWS(jws_header, jws_payload)
        return jws.as_json()

    def parse_with_signature_JWS(self, jws_header: JWSHeader, jws_payload: Json) -> 'JWS':
        """Creates a JWS object."""
        jws_header_json  = json.dumps(jws_header, cls=JWSHeaderEncoder)
        jws_payload_json = json.dumps(jws_payload)  
        signature = self._signature_for(jws_header_json, jws_payload_json)

        return JWS(jws_payload, jws_header, signature)

class JWS():
    payload: Json
    protected: JWSHeader  
    signature: Signature

    def __init__(self, jws_payload, jws_header, signature):
        self.payload = jws_payload
        self.protected = jws_header
        self.signature = signature
    

    def as_json(self) -> Json:
        """Converts the JWS to a base64url encoded string."""
        j = json.dumps(self, cls=JWSEncoder)
        j = json.loads(j)
        return j




class JWSEncoder(json.JSONEncoder):
    """JSON encoder for JWSHeader and JWKey objects."""

    def default(self, obj):
        if isinstance(obj, JWS):
            d = copy.copy(obj.__dict__)
            d['protected'] = url64.encode(JWSHeaderEncoder.default(self, obj.protected))
            d['signature'] = url64.encode(obj.signature)
            d['payload'] = url64.encode(obj.payload)
            return d
        else :
            return json.JSONEncoder.default(self, obj)
