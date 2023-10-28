from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend


import url64
from method.acme_objects import Identifier


def create_csr(
    identifiers: list[Identifier], private_key_path: str = "debug/sk.pem"
) -> str:
    #     # Generate a private key
    # with open(private_key_path, "rb") as key_file:
    #     private_key_bytes = key_file.read()

    # private_key = serialization.load_pem_private_key(private_key_bytes, password=None, backend=default_backend())
    #
    # TODO: SAVE PRIVATE KEYS TO BE USED LATER BY HTTPS SERVER OR LOAD THEM FROM A FILE
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

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


if __name__ == "__main__":
    identifiers = [
        Identifier({"value": "www.example.com", "type": "dns"}),
        Identifier({"value": "www.another-example.com", "type": "dns"}),
        Identifier({"value": "example.com", "type": "dns"}),
    ]
    csr = create_csr(identifiers, "debug/sk.pem")
    print(csr)
