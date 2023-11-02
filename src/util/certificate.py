from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend


import url64
from method.acme_objects import Identifier


def get_private_key():
    # TODO: SAVE PRIVATE KEYS TO BE USED LATER BY HTTPS SERVER OR LOAD THEM FROM A FILE

    return rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )


def create_csr(
    identifiers: list[Identifier], private_key_path: str = "debug/sk.pem"
) -> str:
    private_key = get_private_key()

    # Create a CSR builder
    csr_builder = x509.CertificateSigningRequestBuilder()

    names = [
        x509.NameAttribute(NameOID.COMMON_NAME, identifier.value)
        for identifier in identifiers
    ]
    # Add subject name
    csr_builder = csr_builder.subject_name(x509.Name(names))
    # Create a SAN extension with "example.com" as a DNS name
    san_extension = x509.SubjectAlternativeName(
        [x509.DNSName(identifier.value) for identifier in identifiers]
    )
    # Add the extension to the CSR
    csr_builder = csr_builder.add_extension(san_extension, critical=False)

    # Sign the CSR with the private key
    csr = csr_builder.sign(
        private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend()
    )

    # Serialize the CSR to DER format
    csr_der = csr.public_bytes(encoding=serialization.Encoding.DER)
    with open("debug/csr.der", "wb") as f:
        f.write(csr_der)

    return url64.encode(csr_der)


def get_der_cert_for_pem(pem_cert: bytes) -> bytes:
    """Returns the DER certificate from a PEM certificate."""
    cert = x509.load_pem_x509_certificate(pem_cert, default_backend())
    return cert.public_bytes(encoding=serialization.Encoding.DER)
