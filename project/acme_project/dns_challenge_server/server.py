import logging
import socketserver
from base64 import urlsafe_b64encode

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from dnslib import QTYPE
from dnslib import RR
from dnslib import TXT
from dnslib import A
from dnslib import DNSError
from dnslib import DNSRecord

from acme_project.jws import create_jwk_thumbprint

logger = logging.getLogger(__name__)

tokens: list[str] = []
account_key: ec.EllipticCurvePrivateKey
a_record: str


class DNSServer(socketserver.BaseRequestHandler):
    def handle(self):
        data: bytes = self.request[0].strip()
        logger.debug(f"Received {len(data)} bytes")
        try:
            query_record: DNSRecord = DNSRecord.parse(data)
            response_record = self._create_response(query_record)
            logger.debug(f"response_record = \n{response_record}")
            self.request[1].sendto(response_record.pack(), self.client_address)
        except DNSError:
            logger.exception("Failed parsing DNS request record: " + data.hex(" "))

    def _create_response(self, query_record: DNSRecord) -> DNSRecord:
        reply = query_record.reply()

        if query_record.q.qtype == QTYPE.A:
            logger.debug("query_record.q.qtype == QTYPE.A")
            # Unconditionally return the global a_record value for all A record
            # queries, copying the request name as-is into the response.
            reply.add_answer(
                RR(rname=query_record.q.qname, rtype=QTYPE.A, rdata=A(a_record)),
            )

        elif query_record.q.qtype == QTYPE.TXT and str(query_record.q.qname).startswith(
            "_acme-challenge."
        ):
            logger.debug(
                "query_record.q.qtype == QTYPE.TXT && .startswith(_acme-challenge.)"
            )
            # We don't perform any qname checking here except that it begins
            # with _acme-challenge, since the actual domain could be arbitrary.
            for token in tokens:
                key_authorization = (
                    token.encode("ASCII") + b"." + create_jwk_thumbprint(account_key)
                )
                ka_hash = hashes.Hash(hashes.SHA256())
                ka_hash.update(key_authorization)
                b64_ka_hash = urlsafe_b64encode(ka_hash.finalize()).strip(b"=")

                reply.add_answer(
                    RR(
                        rname=query_record.q.qname,
                        rtype=QTYPE.TXT,
                        rdata=TXT(b64_ka_hash),
                    ),
                )
        else:
            logger.debug(
                f"Ignoring query_record.q.qtype == {QTYPE[query_record.q.qtype]}"
            )

        return reply
