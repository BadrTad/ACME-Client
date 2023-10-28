import hashlib
import ecdsa
from ecdsa import SigningKey, VerifyingKey
from acme_types import Tuple


def generate_keypair() -> Tuple[SigningKey, VerifyingKey]:
    """Generate a keypair."""
    sk: SigningKey = ecdsa.SigningKey.generate(
        curve=ecdsa.NIST256p, hashfunc=hashlib.sha256
    )
    vk: VerifyingKey = sk.get_verifying_key()

    return sk, vk


def load_keypair(path_sk: str, path_vk: str) -> Tuple[SigningKey, VerifyingKey]:
    """Load a keypair from the given paths."""
    with open(path_sk, "rb") as f:
        sk = SigningKey.from_pem(f.read(), hashlib.sha256)

    with open(path_vk, "rb") as f:
        vk = VerifyingKey.from_pem(f.read(), hashlib.sha256)

    return sk, vk


def save_keypair(path, sk: SigningKey, vk: VerifyingKey):
    with open(path + "sk.pem", "wb") as f:
        f.write(sk.to_pem())
    with open(path + "vk.pem", "wb") as f:
        f.write(vk.to_pem())
