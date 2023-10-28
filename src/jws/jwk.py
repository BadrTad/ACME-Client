import json
import copy
import url64
import hashlib


class JWKey:
    """JWK implementation."""

    def __init__(self, **kargs) -> None:
        self.kty: str = kargs.get("kty", "EC")
        self.crv: str = kargs.get("crv", "P-256")

        self.x: str = kargs.get("x")
        self.y: str = kargs.get("y")

    def thumbprint(self, base64Url=True) -> str | bytes:
        """Returns the thumbprint of the JWK."""

        jwk_str: str = (
            json.dumps(self.__dict__, sort_keys=True)
            .replace(" ", "")
            .replace("\n", "")
            .replace("\x00", "")
        )
        jwk_hash = hashlib.sha256(jwk_str.encode("utf-8")).digest()

        return url64.encode(jwk_hash) if base64Url else jwk_hash

    def __repr__(self) -> str:
        return f"""
        JWKey:
            crv: {self.crv}
            kty: {self.kty}
            x: {self.x}
            y: {self.y}
        """

    def as_json(self) -> dict[str, str]:
        return copy.copy(self.__dict__)


class JWKeyEncoder(json.JSONEncoder):
    """JSON encoder for JWKey objects."""

    def default(self, obj):
        if isinstance(obj, JWKey):
            d = copy.copy(obj.__dict__)
            return d
        return json.JSONEncoder.default(self, obj)
