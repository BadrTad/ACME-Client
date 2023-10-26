from jws.jwk import JWKey
from jwcrypto.jwk import JWK as jwcrypto_JWK
import pytest


@pytest.fixture
def jwcrypto_jwk():
    """Returns a JWK object from jwcrypto."""
    with open('debug/keypair.pem', 'rb') as f:
        s = f.read()
        
    return jwcrypto_JWK.from_pem(s)

@pytest.fixture
def key_json() -> dict[str,str]:
  return {
      "kty": "EC",
      "crv": "P-256",
      "x": "_wpHBwxURlHgpl38hr4txN6XflCkW00d52ZzIK6OijE",
      "y": "NQBMChTjhIKxErB7mE4NO1h0SJ2MMZHH1huo3gG1os8"
  }

def test_jwk_from_json(jwcrypto_jwk: jwcrypto_JWK, key_json: dict[str,str]):
    jwk = JWKey(**key_json)
    d = jwcrypto_jwk.export_public(as_dict=True)
    assert jwk.x == d['x']
    assert jwk.y == d['y']
    assert jwk.crv == d['crv']
    assert jwk.kty == d['kty']
    assert jwk.thumbprint() == jwcrypto_jwk.thumbprint()

    