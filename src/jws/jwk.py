import copy 
import json
import url64

class JWKey():
    """JWK implementation."""

    def __init__(self, x: int, y: int) -> None:
        self.kty: str = "EC"
        self.crv: str = "P-256"
        self.use: str = "sig"
        self.x: bytes = int(x).to_bytes(32, byteorder='big')
        self.y: bytes = int(y).to_bytes(32, byteorder='big')

class JWKeyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, JWKey):
            d = copy.copy(obj.__dict__)
            d['x'] = url64.encode(obj.x)
            d['y'] = url64.encode(obj.y)

            return d
        return json.JSONEncoder.default(self, obj) 
