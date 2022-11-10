from base64 import urlsafe_b64encode

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID


def create_b64url_csr(key: ec.EllipticCurvePrivateKey, domains: list[str]) -> str:
    """Create a CSR from the private key and domains specified. Return the
    base64url encoding of the DER format bytes. Multiple domains can be specified.

    Parameters
    ----------
    key : ec.EllipticCurvePrivateKey
        The private key used for the ACME client as well.
    domains : list[str]
        The domains to request a certificate for. The first one will be the
        commonName, the rest will be subjectAltNames.

    Returns
    -------
    bytes
        The base64url encoding of the DER encoding of the CSR.

    Raises
    ------
    Exception
        When the domain list has an invalid length.
    """
    if len(domains) == 0:
        raise Exception("A zero-length list was passed to create_csr_der!")

    csr_builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    # Provide various details about who we are.
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "CH"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Zürich"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, "Zürich"),
                    x509.NameAttribute(
                        NameOID.ORGANIZATION_NAME, "ETH Zürich Network Security"
                    ),
                    x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
                ]
            )
        )
        .add_extension(
            x509.SubjectAlternativeName(list(map(x509.DNSName, domains))),
            critical=False,
        )
    )
    # Sign the CSR with our private key.
    csr = csr_builder.sign(key, hashes.SHA256())
    return (
        urlsafe_b64encode(csr.public_bytes(encoding=Encoding.DER))
        .strip(b"=")
        .decode("ASCII")
    )
