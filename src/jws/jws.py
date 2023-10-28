import json
import url64
import copy
from util.crypto import SigningKey, VerifyingKey
from acme_types import Json, Signature, Tuple

from jws.jwk import JWKey
from jws.jws_header import JWSHeader, JWSHeaderEncoder


class JWSFactory:
    """Factory for creating JWS objects."""

    def __init__(self, signing_key: SigningKey, verifying_key: VerifyingKey):
        self._signing_key: SigningKey = signing_key

        # Craete jwk from verifying key
        x, y = self._get_public_key_point(verifying_key)
        self.jwk = JWKey(x=x, y=y)

    def __check_payload(self, jws_payload: Json | str) -> bool:
        try:
            _ = json.dumps(jws_payload)
            return True
        except TypeError:
            return False

    def _parse_payload(payload: Json | str) -> str:
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

    def _get_public_key_point(
        self, verifying_key, as_b64url=True
    ) -> Tuple[str | int, int | str]:
        """Returns the public key as EC point."""
        x = verifying_key.pubkey.point.x()
        y = verifying_key.pubkey.point.y()
        if as_b64url:
            x = url64.encode(int(x).to_bytes(32, byteorder="big"))
            y = url64.encode(int(y).to_bytes(32, byteorder="big"))
            return x, y
        else:
            return x, y

    def _parse_with_signature_JWS(
        self, jws_header: JWSHeader, jws_payload: str
    ) -> "JWS":
        """Creates a JWS object."""
        jws_header_str = json.dumps(jws_header, cls=JWSHeaderEncoder)
        signature = self._signature_for(jws_header_str, jws_payload)

        return JWS(jws_payload, jws_header, signature)

    def build_JWS_with_jwk(
        self, jws_header_params: Json, jws_payload: Json | str
    ) -> Json:
        """Builds a JWS object."""
        assert self.__check_payload(jws_payload)

        jws_header = JWSHeader(**jws_header_params, jwk=self.jwk)
        payload = JWSFactory._parse_payload(jws_payload)
        jws = self._parse_with_signature_JWS(jws_header, payload)

        return jws.as_json()

    def build_JWS_with_kid(
        self, jws_header_params: Json, jws_payload: Json | str
    ) -> Json:
        """Builds a JWS object."""
        assert "kid" in jws_header_params
        assert self.__check_payload(jws_payload)
        jws_header = JWSHeader(**jws_header_params)
        payload = JWSFactory._parse_payload(jws_payload)
        jws = self._parse_with_signature_JWS(jws_header, payload)
        return jws.as_json()


class JWS:
    payload: Json
    protected: JWSHeader
    signature: Signature

    def __init__(self, jws_payload, jws_header, signature):
        self.payload = jws_payload
        self.protected = jws_header
        self.signature = signature

    def as_json(self) -> Json:
        """Converts the JWS to a base64url encoded string."""
        d = copy.copy(self.__dict__)
        d["protected"] = url64.encode(json.dumps(self.protected, cls=JWSHeaderEncoder))
        d["signature"] = url64.encode(self.signature)
        d["payload"] = url64.encode(self.payload)
        return d
