import logging
import threading

from cryptography.hazmat.primitives.asymmetric import ec

from acme_project.acme_client.challenge import Challenge
from acme_project.http_challenge_server import server

logger = logging.getLogger(__name__)


def start_thread(key: ec.EllipticCurvePrivateKey, challenges: list[Challenge]):
    """Start the HTTP Challenge Server in another thread.

    Parameters
    ----------
    key : ec.EllipticCurvePrivateKey
        The private account key used for the ACME client.
    challenges : list[Challenge]
        The http-01 challenges to put on the HTTP server.
    """
    # Set the tokens and account key globals in the server
    server.tokens = [challenge.additional["token"] for challenge in challenges]
    server.account_key = key

    logger.debug(f"server.tokens = {str(server.tokens)}")

    # Run the server in a separate thread, while we signal to the ACME server
    # and poll its responses.
    http_challenge_thread = threading.Thread(
        target=lambda: server.app.run(host="0.0.0.0", port=5002, debug=False),
        # Quit when main thread exists
        daemon=True,
    )
    http_challenge_thread.start()
