import argparse
import os
import threading

from cryptography.hazmat.primitives.asymmetric import ec

from acme_project import http_challenge_server
from acme_project import https_server
from acme_project.acme_client.challenge import Challenge
from acme_project.acme_client.client import ACMEClient

parser = argparse.ArgumentParser(
    prog="Yuto Takano ACME Project",
    description=f"""
The ACME Project submission for Yuto Takano.
Version: 1.0.0
Path: {os.path.abspath(os.path.dirname(__file__))}
""",
    formatter_class=argparse.RawTextHelpFormatter,
)
parser.add_argument(
    "challenge_type",
    choices=["http01", "dns01"],
    help="The ACME challenge type taht the client should perform. Valid values are http01 and dns01 for http-01 and dns-01 respectively.",
)
parser.add_argument(
    "--dir",
    required=True,
    help="Directory URL of the ACME server that should be used",
)
parser.add_argument(
    "--record",
    required=True,
    help="IPv4 address which must be returned by the DNS server for all A-record queries",
)
parser.add_argument(
    "--domain",
    action="append",
    required=True,
    help="Domain for which to request the certificate. If multiple are present, a single certificate for multiple domains will be requested. Wildcard domains have no special flag and should be denoted by e.g. *.example.net",
)
parser.add_argument(
    "--revoke",
    action="store_true",
    help="If present, immediately revoke the certificate after obtaining it. Regardless, the HTTPS server will start and used the obtained certificate.",
)


def start_http_challenge_server(
    key: ec.EllipticCurvePrivateKey, challenges: list[Challenge]
):
    # Set the tokens and account key globals in the server
    http_challenge_server.tokens = [
        challenge.additional["token"] for challenge in challenges
    ]
    http_challenge_server.account_key = key

    # Run the server in a separate thread, while we signal to the ACME server
    # and poll its responses.
    http_challenge_thread = threading.Thread(
        target=lambda: http_challenge_server.app.run(host="::", port=5002, debug=False),
        # Quit when main thread exists
        daemon=True,
    )
    http_challenge_thread.start()


def start_dns_challenge_server(
    key: ec.EllipticCurvePrivateKey, challenges: list[Challenge]
):
    pass


def main() -> None:
    args = parser.parse_args()
    client = ACMEClient(args.dir)
    (order_endpoint, auths) = client.request_order(domains=args.domain)

    challenge_type_rfc = "http-01" if args.challenge_type == "http01" else "dns-01"

    # Gather all the challenges relevant to this challenge type, regardless
    # of the associated identifier/authorization, since we will be using one
    # single server for all the domains in this assignment.
    relevant_challenges = [
        challenge
        for auth in auths
        for challenge in auth.challenges
        if challenge.type == challenge_type_rfc
    ]

    # Temporarily start either the HTTP or DNS server until we receive
    # confirmation that the challenge was validated.
    if args.challenge_type == "http01":
        start_http_challenge_server(client.private_key, relevant_challenges)
    else:
        start_dns_challenge_server(client.private_key, relevant_challenges)

    # At this point, we have deployed responses for at least one challenge for
    # every domain identifier. We can request each fulfilled challenge to be
    # validated.
    for challenge in relevant_challenges:
        client.request_challenge_validation(challenge)

    # Now since all identifiers are just waiting for validation, we block and
    # wait for the completion. On errors, this function will raise an Exception.
    client.await_validation(order_endpoint)

    # Now that we have formal validated Authorizations for each of our identifiers,
    # send a formal CSR.
    client.request_certificate(order_endpoint)

    # Block and wait for the certificate chain PEM, then download it
    cert = client.await_certificate(order_endpoint)
    with open("./https_cert.pem", "w", encoding="UTF-8") as f:
        f.write(cert.pem_chain)
    with open("./https_key.pem", "w", encoding="UTF-8") as f:
        f.write(cert.key)

    # Deactivate the ACME Server account just in case to prevent polluting the
    # account database.
    client.deactivate()

    https_server.app.run(
        host="::",
        port=5001,
        debug=False,
        ssl_context=("./https_cert.pem", "./https_key.pem"),
    )
