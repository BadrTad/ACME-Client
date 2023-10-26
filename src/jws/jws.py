import json
import url64
import copy
from util.crypto import SigningKey, VerifyingKey
from acme_types import Json, Signature, Tuple

from jws.jwk import JWKey
from jws.jws_header import JWSHeader, JWSHeaderEncoder


class JWSFactory():
    """Factory for creating JWS objects."""
    _signing_key: SigningKey
    verifying_key: VerifyingKey

    def __init__(self, signing_key: SigningKey, verifying_key: VerifyingKey):
        self._signing_key = signing_key
        self.verifying_key = verifying_key

    def __check_payload(self, jws_payload: Json|str) -> bool:
        
        try:
            _ = json.dumps(jws_payload)
            return True
        except TypeError:
            return False

    def _parse_payload(payload: Json|str) -> str:
        match payload:
            case str():
                return payload
            case _:
                return json.dumps(payload)
        

    def _signature_for(self, jws_header: str, jws_payload: str) -> Signature:
        """Computes the signature for a JWS object."""

        jws_header = url64.encode(jws_header)
        jws_payload = url64.encode(jws_payload) 

        to_sign = jws_header + "." + jws_payload  
        s_bytes = self._signing_key.sign(to_sign.encode("utf-8"))

        return s_bytes

    def _get_public_key_point(self) -> Tuple[int, int]:
        """Returns the public key as EC point."""
        x = self.verifying_key.pubkey.point.x()
        y = self.verifying_key.pubkey.point.y()
        return x, y

    def _parse_with_signature_JWS(self, jws_header: JWSHeader, jws_payload: str) -> 'JWS':
        """Creates a JWS object."""
        jws_header_str = json.dumps(jws_header, cls=JWSHeaderEncoder)
        signature = self._signature_for(jws_header_str, jws_payload)

        return JWS(jws_payload, jws_header, signature)

    def build_JWS_with_jwk(self, jws_header_params: Json, jws_payload: Json|str) -> Json:
        """Builds a JWS object."""
        assert self.__check_payload(jws_payload)

        x, y = self._get_public_key_point()
        jwk = JWKey(x, y)

        jws_header = JWSHeader.with_jwk(**jws_header_params, jwk=jwk)

        payload = JWSFactory._parse_payload(jws_payload)
        jws = self._parse_with_signature_JWS(jws_header, payload)

        return jws.as_json()

    def build_JWS_with_kid(self, jws_header_params: Json, jws_payload: Json|str) -> Json:
        """Builds a JWS object."""
        assert "kid" in jws_header_params
        assert self.__check_payload(jws_payload)
        jws_header = JWSHeader.with_kid(**jws_header_params)
        payload = JWSFactory._parse_payload(jws_payload)
        jws = self._parse_with_signature_JWS(jws_header, payload)
        return jws.as_json()


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
        else:
            return json.JSONEncoder.default(self, obj)
