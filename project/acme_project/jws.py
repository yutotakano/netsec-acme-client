import json
from base64 import urlsafe_b64encode

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.utils import int_to_bytes


def create_jwk(key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    return {
        # Only the minimum required keys should be here, and in lexicographic
        # order. This is irrelevant for the newAccount ACME server registration,
        # but becomes vital for the JWK Thumbprint generation when responding to
        # challenges, see RFC 8555 Section 8.1 and RFC 7638 Section 3.2.
        "crv": "P-256",
        "kty": "EC",
        "x": urlsafe_b64encode(
            int_to_bytes(
                key.public_key().public_numbers().x,
                (key.curve.key_size + 7) // 8,
            )
        )
        .strip(b"=")
        .decode("ASCII"),
        "y": urlsafe_b64encode(
            int_to_bytes(
                key.public_key().public_numbers().y,
                (key.curve.key_size + 7) // 8,
            )
        )
        .strip(b"=")
        .decode("ASCII"),
    }


def create_flattened_jws(
    key: ec.EllipticCurvePrivateKey, protected_header: str, payload: str
) -> str:
    b64url_payload = urlsafe_b64encode(payload.encode("UTF-8")).strip(b"=")

    b64url_protected_header = urlsafe_b64encode(protected_header.encode("UTF-8")).strip(
        b"="
    )

    # The key.sign() method on EllipticCurvePublicKey returns a DSS format,
    # whereas we want the pure concatenation of r and s bytes (RFC 7518
    # Section 3.4 for procedure specific to ES256, i.e. ECDSA P-256 SHA256)
    (r, s) = decode_dss_signature(
        key.sign(
            b64url_protected_header + b"." + b64url_payload,
            signature_algorithm=ec.ECDSA(hashes.SHA256()),
        )
    )
    jws_signature = int_to_bytes(r, (key.curve.key_size + 7) // 8) + int_to_bytes(
        s, (key.curve.key_size + 7) // 8
    )
    b64url_jws_signature = urlsafe_b64encode(jws_signature).strip(b"=")

    return json.dumps(
        {
            "protected": b64url_protected_header.decode("ASCII"),
            "payload": b64url_payload.decode("ASCII"),
            "signature": b64url_jws_signature.decode("ASCII"),
        }
    )


def create_jwk_thumbprint(key: ec.EllipticCurvePrivateKey) -> bytes:
    thumbprint = hashes.Hash(hashes.SHA256())
    thumbprint.update(
        json.dumps(
            create_jwk(key=key),
            # Prevent whitespace between items and between key/value, which the
            # default will add. JWK Thumbprint should be computed with zero
            # whitespace as per RFC 7638 Section 3.
            separators=(",", ":"),
        ).encode("UTF-8")
    )
    return urlsafe_b64encode(thumbprint.finalize()).strip(b"=")
