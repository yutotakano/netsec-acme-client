# -*- coding: utf-8 -*-
"""This module contains the CLI functionality, and the flow invoking the various
other components of this project.

The main components of this project are:
    acme_project.acme_client - The ACME client to interface with the ACME server
    acme_project.dns_challenge_server - The DNS server to respond to dns-01
    acme_project.http_challenge_server - The HTTP server to respond to http-01
    acme_project.https_server - The HTTPS server to serve the acquired certificate
    acme_project.shutdown_server - The server to respond to /shutdown
"""
import argparse
import logging
import os
import sys

from cryptography.hazmat.primitives import serialization

from acme_project import dns_challenge_server
from acme_project import http_challenge_server
from acme_project import https_server
from acme_project import shutdown_server
from acme_project.acme_client.challenge import Challenge
from acme_project.acme_client.client import ACMEClient

logger = logging.getLogger(__name__)

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
parser.add_argument(
    "--log",
    default="debug",
    choices=["debug", "info", "warning", "error", "critical"],
    help="The logging level to assign to the default standard output handler",
)


def main() -> None:
    args = parser.parse_args()

    # Change the root log level
    logging.getLogger().setLevel(args.log.upper())
    logger.info(f"Log level set to {args.log.upper()}")

    client = ACMEClient(args.dir)

    # Map the argument to the RFC-compatible challenge names
    parsed_arg_chal_type = "http-01" if args.challenge_type == "http01" else "dns-01"

    # Place an order
    (order_endpoint, auths) = client.request_order(domains=args.domain)

    # Create a dictionary sorting the http and dns challenges. We don't care
    # about the identifier/authorization associated with each challenge, since
    # for this assignment everything is on one server.
    relevant_challenges: dict[str, list[Challenge]] = {}
    for chal_type in ["http-01", "dns-01"]:
        relevant_challenges[chal_type] = [
            challenge
            for auth in auths
            for challenge in auth.challenges
            if challenge.type == chal_type
        ]
    logger.debug("relevant_challenges = " + str(relevant_challenges))

    # Start the DNS server regardless of the challenge type, since Pebble needs
    # to resolve the DNS even for the http-01 challenge.
    dns_challenge_server.start_thread(
        client.private_key, args.record, relevant_challenges[parsed_arg_chal_type]
    )
    dns_challenge_server.server_ready.wait()

    # Temporarily start the HTTP server.
    if args.challenge_type == "http01":
        http_challenge_server.start_thread(
            client.private_key, relevant_challenges[parsed_arg_chal_type]
        )

    # At this point, we have deployed responses for at least one challenge for
    # every domain identifier. We can request each fulfilled challenge to be
    # validated.
    for challenge in relevant_challenges[parsed_arg_chal_type]:
        client.request_challenge_validation(challenge)

    # Now since all identifiers are just waiting for validation, we block and
    # wait for the completion. On errors, this function will raise an Exception.
    client.await_validation(order_endpoint)

    # Now that we have formal validated Authorizations for each of our identifiers,
    # send a formal CSR.
    client.request_certificate(order_endpoint)

    # Block and wait for the certificate chain PEM, then download it
    (leaf_cert, leaf_key, pem_chain) = client.await_certificate(order_endpoint)

    with open("./https_cert.pem", "wb") as f:
        f.write(pem_chain)
        logger.debug("written certificate PEM to " + f.name)

    with open("./https_key.pem", "wb") as f:
        f.write(
            leaf_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        logger.debug("written certificate private key PEM to " + f.name)

    # If the revoke flag is set, immediately revoke it
    if args.revoke:
        client.revoke_certificate(leaf_cert)

    # Start the main server in a separate thread. This allows us to wait for the
    # shutdown in the main thread and close the entire program together with all
    # child threads when the shutdown semaphore is set.
    https_server.start_thread("./https_cert.pem", "./https_key.pem")

    # Await the /shutdown request in a separate thread, while in the main thread
    # we wait for the semaphore that the shutdown was requested.
    shutdown_server.start_thread()

    # Block and wait until shutdown is requested
    shutdown_server.server.shutdown_requested.wait()

    # Deactivate the ACME Server account just in case to prevent polluting the
    # account database.
    client.deactivate()

    sys.exit(0)
