import json
import logging
from abc import ABC
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ec
from requests import Request
from requests import Response
from requests import Session

from acme_project.jws import create_flattened_jws
from acme_project.jws import create_jwk

logger = logging.getLogger(__name__)


class Endpoint(ABC):
    url = ""
    method = "GET"
    headers: dict[str, str] = {}
    use_kid: bool = False
    use_jwk: bool = False

    def retrieve(
        self,
        key: ec.EllipticCurvePrivateKey,
        payload: Optional[str] = None,
        nonce: Optional[str] = None,
        kid: Optional[str] = None,
        retry_limit: int = 2,
    ) -> Response:
        logger.debug(f"Retrieving {self.method} {self.url}")
        s = Session()
        if self.method == "POST":
            headers = self.headers | {
                "User-Agent": "takanoy-acme-project/1.0.0",
                "Content-Type": "application/jose+json",
            }
            post_data = self._create_base64_jws(payload, nonce, key, kid)
            logger.debug(f"post_data = \n{post_data}")
        else:
            headers = self.headers | {"User-Agent": "takanoy-acme-project/1.0.0"}
            post_data = None

        req = Request(self.method, self.url, headers=headers, data=post_data)
        prepped = s.prepare_request(req)
        response = s.send(prepped, verify="./pebble.minica.pem")

        # Retry up to twice (arbitrary) on a badNonce, since we might have a
        # truly bad nonce.
        while (
            response.status_code == 400
            and response.json()["type"] == "urn:ietf:params:acme:error:badNonce"
            and retry_limit > 0
        ):
            logger.debug(f"badNonce response, retry_limit = {retry_limit}")
            return self.retrieve(
                key, payload, response.headers["Replay-Nonce"], kid, retry_limit - 1
            )

        return response

    def _create_base64_jws(
        self,
        payload: Optional[str],
        nonce: Optional[str],
        key: ec.EllipticCurvePrivateKey,
        kid: Optional[str],
    ) -> str:
        """
        Create the POST body.
        """
        if self.method != "POST":
            raise Exception("Base64 JWS shouldn't be used with non-POST requests!")
        if payload is None or nonce is None:
            raise Exception("Both payload and replay-nonce are required for JWS!")

        if self.use_kid and kid is None:
            raise Exception("This endpoint requires the kid to be passed in!")

        protected_header = {
            # ES256 is guaranteed to be supported by the server, per RFC Section 6.2
            "alg": "ES256",
            "nonce": nonce,
            "url": self.url,
        }

        if self.use_kid:
            protected_header |= {"kid": kid}
        elif self.use_jwk:
            protected_header |= {"jwk": create_jwk(key)}

        return create_flattened_jws(
            key=key, protected_header=json.dumps(protected_header), payload=payload
        )
