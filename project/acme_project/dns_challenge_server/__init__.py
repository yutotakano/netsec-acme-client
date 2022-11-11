import logging
import socketserver
import threading

from cryptography.hazmat.primitives.asymmetric import ec

from acme_project.acme_client.challenge import Challenge
from acme_project.dns_challenge_server import server

logger = logging.getLogger(__name__)


def start_thread(
    key: ec.EllipticCurvePrivateKey, a_record: str, challenges: list[Challenge]
):
    """Start the DNS Challenge Server in a separate thread.

    Parameters
    ----------
    key : ec.EllipticCurvePrivateKey
        The private account key used by the ACME Client.
    a_record : str
        The value to respond with for any A record queries.
    challenges : list[Challenge]
        The dns-01 challenges to put on the TXT records.
    """
    # Set the tokens and account key globals in the server
    server.a_record = a_record
    server.tokens = [challenge.additional["token"] for challenge in challenges]
    server.account_key = key

    logger.debug(f"server.tokens = {str(server.tokens)}")

    dns_challenge_thread = threading.Thread(
        target=socketserver.UDPServer(("", 10053), server.DNSServer).serve_forever,
        daemon=True,
    )
    dns_challenge_thread.start()
