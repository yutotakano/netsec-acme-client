from cryptography.hazmat.primitives.asymmetric import ec
from flask import Flask
from flask import abort

from acme_project.jws import create_jwk_thumbprint

app = Flask(__name__)
tokens: list[str] = []
account_key: ec.EllipticCurvePrivateKey


@app.route("/.well-known/acme-challenge/<requested_token>")
def http_challenge(requested_token: str) -> bytes:
    """The http-01 ACME Identifier Challenge endpoint. Returns the Authorization
    Key upon request.

    Parameters
    ----------
    requested_token : str
        The token that the ACME Server (or someone else) tried to visit.

    Returns
    -------
    bytes
        If the requested token is valid, this contains the Authorization Key for
        the token.
    """
    global tokens
    global account_key

    # If the token is not one we should respond to, pretend it's a 404
    if requested_token not in tokens:
        abort(404)

    # Construct the key authorization and set that as the return body
    key_authorization = (
        requested_token.encode("ASCII") + b"." + create_jwk_thumbprint(account_key)
    )
    return key_authorization
