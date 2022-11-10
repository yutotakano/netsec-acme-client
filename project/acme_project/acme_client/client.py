import dataclasses
import json
from base64 import urlsafe_b64encode
from time import sleep
from typing import Any

import urllib3.util.retry as urllib3
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from acme_project.acme_client.account import Account
from acme_project.acme_client.account import AccountStub
from acme_project.acme_client.account import MainAccountEndpoint
from acme_project.acme_client.authorization import Authorization
from acme_project.acme_client.authorization import GetAuthorizationEndpoint
from acme_project.acme_client.certificate import create_b64url_csr
from acme_project.acme_client.challenge import Challenge
from acme_project.acme_client.directory import Directory
from acme_project.acme_client.directory import DirectoryEndpoint
from acme_project.acme_client.order import GetOrderEndpoint
from acme_project.acme_client.order import Order
from acme_project.acme_client.order import OrderStub


class ACMEClient:
    last_replay_nonce: str
    directory: Directory
    private_key: ec.EllipticCurvePrivateKey
    account_endpoint: MainAccountEndpoint
    orders: list[tuple[GetOrderEndpoint, Order]]
    certificate_key: ec.EllipticCurvePrivateKey

    def __init__(self, dir_url: str):
        """On initialisation, retrieve the Directory.

        Parameters
        ----------
        dir_url : str
            The URL to the ACME server directory.
        """
        # RFC 7518: ES256 -> ECDSA P-256 curve with SHA-256 MAC
        self.private_key = ec.generate_private_key(ec.SECP256R1())

        # Generate another pair for the certificate signing request. As per RFC
        # 8555 Section 11.1 this keypair MUST be different to the account keys.
        self.certificate_key = ec.generate_private_key(ec.SECP256R1())

        self.directory = self._retrieve_directory(dir_url)

        self.last_replay_nonce = self._retrieve_new_nonce()

        self.orders = []

    def request_order(
        self, domains: list[str]
    ) -> tuple[GetOrderEndpoint, list[Authorization]]:
        """Create an account on the ACME server, set up an order for the
        requested identifiers, and return the list of Authorizations that need
        to be completed for the certificate to be issued.

        Parameters
        ----------
        domains : list[str]
            List of domain names (wildcard allowed) to request the certificate for.

        Returns
        -------
        list[Authorization]
            The list of Authorizations that need to be completed for the
            certificate to be issued. Upon completion, the client needs to
            manually call .finalize().
        """
        self._create_account()
        order_endpoint, order = self._create_order(domains)
        self.orders.append((order_endpoint, order))

        # Only return pending authorizations
        return (
            order_endpoint,
            [
                auth
                for auth in map(self._retrieve_authorization, order.authorization_urls)
                if auth.status == "pending"
            ],
        )

    def deactivate(self):
        """Deactivate the account used by this ACME Client."""
        self._deactivate_account()

    def request_challenge_validation(self, challenge: Challenge) -> None:
        """Request the ACME Server to validate the specified challenge. Does not
        wait for the actual validation itself, this should be done via polling
        the authorization endpoint.

        Parameters
        ----------
        challenge : Challenge
            The challenge that was completed and needs validation.

        Raises
        ------
        Exception
            When the server fails to accept the challenge response
        Exception
            When the challenge was immediately rejected with status=invalid
        """
        response = challenge.respond_url.retrieve(
            key=self.private_key,
            payload="{}",
            nonce=self.last_replay_nonce,
            kid=self.account_endpoint.url,
        )

        # Use replay nonce for future requests
        self.last_replay_nonce = response.headers["Replay-Nonce"]

        # RFC Section 7.5.1 specifies it has to return 200
        if response.status_code != 200:
            raise Exception(
                "Server failed to accept challenge response: " + response.text
            )

        updated_chal = Challenge.from_json(response.json())

        # We now just have to wait until the Authorization resource has an
        # updated status.

        # Just in case, we check if the challenge was immediately
        # rejected.
        if updated_chal.status == "invalid":
            raise Exception(
                "Server immediately invalidated the challenge: " + response.text
            )

    def await_validation(self, order_endpoint: GetOrderEndpoint):
        """Poll the Authorization endpoints until we have either an "invalid" or
        "valid" status, which are the only two options at this stage (Page 32
        of RFC 8555). This function is blocking until the validation succeeds or
        fails on the ACME Server.

        Parameters
        ----------
        order_endpoint : GetOrderEndpoint
            The endpoint for the order to await.

        Raises
        ------
        Exception
            When the identifier authorization failed and the status of the
            authorization is now 'invalid'
        Exception
            When the encompassing Order has a status that's not 'ready' despite
            all of its authorizations being valid.
        """

        # Get the (outdated) local copy of the order from the endpoint
        order = self._find_order(order_endpoint)

        # We do this individually for each authorization in sequence, since it
        # makes it easier to reason about.
        for endpoint in order.authorization_urls:
            # Retrieve the authorization, taking into account any Retry-After
            # headers automatically
            auth = self._retrieve_authorization(endpoint)
            while auth.status not in ["valid", "invalid"]:
                # If there were no Retry-After headers or if the wait wasn't
                # enough, wait 5 seconds which should be more than enough.
                sleep(5)
                auth = self._retrieve_authorization(endpoint)

            if auth.status == "invalid":
                # If it was invalid, auth.challenges contains only the challenges
                # that errored.
                raise Exception(
                    "Identifier authorization failed: "
                    + ", ".join(map(lambda x: str(x.error), auth.challenges))
                )

        # Once we polled all the authorization endpoints and no Exceptions were
        # raised, verify that the encompassing Order for this account is now
        # in a "ready" state.
        response = order_endpoint.retrieve(
            key=self.private_key,
            payload="",
            nonce=self.last_replay_nonce,
            kid=self.account_endpoint.url,
        )

        # Use replay nonce for future requests
        self.last_replay_nonce = response.headers["Replay-Nonce"]

        if Order.from_json(response.json()).status != "ready":
            raise Exception(
                "Order not ready despite all authorizations being valid...: "
                + response.text
            )

    def request_certificate(self, order_endpoint: GetOrderEndpoint) -> Order:
        """Send a CSR to the ACME Server and return the updated order state.

        Parameters
        ----------
        order_endpoint : GetOrderEndpoint
            The endpoint for the order to send a CSR for. Its challenges must
            have been validated.

        Returns
        -------
        Order
            The updated order state as on the ACME server.

        Raises
        ------
        Exception
            When the Order wasn't in the 'ready' state. Are all challenges
            validated?
        Exception
            When the server failed to accept the CSR in a non-200 return code.
        Exception
            When the server failed to validate the order and its authorizations.
        Exception
            When the server believes there are outstanding authorizations to
            complete.
        """
        order = self._find_order(order_endpoint)
        b64url_csr = create_b64url_csr(
            key=self.certificate_key,
            domains=list(map(lambda x: x["value"], order.identifiers)),
        )
        response = order.finalize.retrieve(
            key=self.private_key,
            payload=json.dumps({"csr": b64url_csr}),
            nonce=self.last_replay_nonce,
            kid=self.account_endpoint.url,
        )

        # Use replay nonce for future requests
        self.last_replay_nonce = response.headers["Replay-Nonce"]

        if response.status_code == 403 and response.json()["type"] == "orderNotReady":
            # Shouldn't happen in normal flow, but if the order wasn't ready yet,
            # the server will respond 403 as per RFC Section 7.4
            raise Exception(
                "Order wasn't in the 'ready' state to request a certificate! "
                + response.text
            )

        # RFC Section 7.4 specifies it has to return 200
        if response.status_code != 200:
            raise Exception(
                "Server failed to accept the CSR: "
                + b64url_csr
                + "\nError: "
                + response.text
            )

        updated_order = Order.from_json(response.json())
        if updated_order.status == "invalid":
            raise Exception("Server invalidated the order: " + str(updated_order))
        elif updated_order.status == "pending":
            raise Exception(
                "Server believes auths are not completed, check the 'authorizations' field for pending authorizations: "
                + str(updated_order)
            )
        elif updated_order.status == "ready":
            print("??? Server ignored our initial CSR, retrying...")
            return self.request_certificate(order_endpoint)

        # Valid order states at this point are 'processing', or 'valid'. The
        # former means we have to wait a bit, potentially by the amount indicated
        # in the Retry-After header. The latter means it's ready for download.
        # We will return here and leave it up to the caller to decide what to do
        # next.
        return updated_order

    def await_certificate(
        self, order_endpoint: GetOrderEndpoint
    ) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
        # Re-retrieve the Order endpoint, although we may have just received an
        # updated Order when we posted the CSR. This is to reduce coupling and
        # perhaps even allow the server to give time to issue the certificate.
        response = order_endpoint.retrieve(
            key=self.private_key,
            payload="",
            nonce=self.last_replay_nonce,
            kid=self.account_endpoint.url,
        )

        # Use replay nonce for future requests
        self.last_replay_nonce = response.headers["Replay-Nonce"]

        if response.status_code != 200:
            raise Exception("Server failed to accept the CSR: " + response.text)

        order = Order.from_json(response.json())

        while order.status == "processing":
            if "Retry-After" in response.headers:
                sleep(
                    urllib3.Retry().parse_retry_after(response.headers["Retry-After"])
                )
            else:
                sleep(5)
            return self.await_certificate(order_endpoint)

        if order.status != "valid":
            # The order status changed to something other than processing and
            # valid, but we were sure it was processing or valid before calling
            # this function (within request_certificate).
            raise Exception(
                "The order was invalidated while processing the CSR!"
                + "Are you sure you called await_certificate after request_certificate?"
                + str(order)
            )
        if order.certificate is None:
            raise Exception(
                "The order is valid and yet it doesn't have a certificate. "
                + "Is it a bug in the ACME Server? "
                + str(order)
            )

        response = order.certificate.retrieve(
            key=self.private_key,
            payload="",
            nonce=self.last_replay_nonce,
            kid=self.account_endpoint.url,
        )
        return (x509.load_pem_x509_certificate(response.content), self.certificate_key)

    def revoke_certificate(self, cert: x509.Certificate):
        """Revoke the specified certificate.

        Parameters
        ----------
        cert : Certificate
            The certificate to be revoked.

        Raises
        ------
        Exception
            When the server fails to revoke the certificate.
        """
        response = self.directory.revoke_cert_endpoint.retrieve(
            key=self.private_key,
            payload=json.dumps(
                {
                    "certificate": (
                        urlsafe_b64encode(
                            cert.public_bytes(encoding=serialization.Encoding.DER)
                        )
                        .strip(b"=")
                        .decode("ASCII")
                    ),
                    # The reason=0 indicates that the reason is unspecified
                    "reason": 0,
                }
            ),
            nonce=self.last_replay_nonce,
            kid=self.account_endpoint.url,
        )

        # Use replay nonce for future requests
        self.last_replay_nonce = response.headers["Replay-Nonce"]

        if response.status_code != 200:
            raise Exception("Server failed to revoke the certificate: " + response.text)

    def _retrieve_directory(self, dir_url: str) -> Directory:
        """Retrieve the directory from the specified ACME server directory URL.

        Returns
        -------
        Directory
            The directory resource retrieved from the ACME server.
        """
        response = DirectoryEndpoint(dir_url).retrieve(key=self.private_key)
        return Directory(response.json())

    def _retrieve_new_nonce(self) -> str:
        """Retrieve a new nonce from the newNonce endpoint in the directory.

        Returns
        -------
        str
            The Replay-Nonce to be used in the next request.
        """
        response = self.directory.new_nonce_endpoint.retrieve(key=self.private_key)
        return response.headers["Replay-Nonce"]

    def _create_account(self) -> Account:
        """Create an account on the ACME server by requesting to the newAccount
        endpoint in the directory. Sets self.account_endpoint to allow kid look-
        ups, and sets self.last_replay_nonce for future requests.

        Returns
        -------
        Account
            The Account resource as currently stored on the server after creation.
        """
        response = self.directory.new_account_endpoint.retrieve(
            key=self.private_key,
            payload=self._class_as_json(
                AccountStub(contact=[], tos_agreed=True, only_return_existing=False)
            ),
            nonce=self.last_replay_nonce,
        )
        # RFC specifies that the Location header points to the account endpoint
        self.account_endpoint = MainAccountEndpoint(response.headers["Location"])

        # Use replay nonce for future requests
        self.last_replay_nonce = response.headers["Replay-Nonce"]

        return Account.from_json(response.json())

    def _deactivate_account(self) -> Account:
        """Deactivates the account associated at self.account_endpoint.
        Sets self.last_replay_nonce for future requests.

        Returns
        -------
        Account
            The Account resource as currently stored on the ACME server.

        Raises
        ------
        Exception
            When the server fails to deactivate the account.
        """
        response = self.account_endpoint.retrieve(
            key=self.private_key,
            payload=self._class_as_json(AccountStub(status="deactivated")),
            nonce=self.last_replay_nonce,
            kid=self.account_endpoint.url,
        )

        # Use replay nonce for future requests
        self.last_replay_nonce = response.headers["Replay-Nonce"]

        # RFC Section 7.3.6 specifies it has to return 200 on success
        if response.status_code != 200:
            raise Exception("Server failed to deactivate account: " + response.text)

        return Account.from_json(response.json())

    def _create_order(self, domains: list[str]) -> tuple[GetOrderEndpoint, Order]:
        """Create an order on the ACME server for the specified domains.
        Sets self.last_replay_nonce for future requests.

        Parameters
        ----------
        domains : list[str]
            List of domains (dns identifiers) to request the certificate order
            for.

        Returns
        -------
        Order
            The Order resource as stored on the ACME server. Contains any
            challenges to be solved within Order.authorization_urls.

        Raises
        ------
        Exception
            When the server could not create a new order.
        """
        response = self.directory.new_order_endpoint.retrieve(
            key=self.private_key,
            nonce=self.last_replay_nonce,
            kid=self.account_endpoint.url,
            payload=self._class_as_json(
                OrderStub(
                    identifiers=list(
                        map(lambda d: {"type": "dns", "value": d}, domains)
                    )
                )
            ),
        )

        # Use replay nonce for future requests
        self.last_replay_nonce = response.headers["Replay-Nonce"]

        # RFC Section 7.4 specifies it has to return 201 on success
        if response.status_code != 201:
            raise Exception(
                "Server was unwilling to issue an order for the requested certificate: "
                + response.text
            )

        order_url = response.headers["Location"]

        return (GetOrderEndpoint(order_url), Order.from_json(response.json()))

    def _find_order(self, order_endpoint: GetOrderEndpoint) -> Order:
        """Dereference the GetOrderEndpoint to get the Order, from the list of
        orders stored in this account instance. This is all local, and does not
        query the ACME Server.

        Parameters
        ----------
        order_endpoint : GetOrderEndpoint
            The order endpoint to deference.

        Returns
        -------
        Order
            The order.
        """
        matching_orders = list(
            filter(lambda tup: tup[0] == order_endpoint, self.orders)
        )

        if len(matching_orders) == 0:
            raise Exception(
                "No matching orders found locally for endpoint " + order_endpoint.url
            )

        # There should only be one matching order, we take the first tuple element
        # of that.
        return matching_orders[0][1]

    def _retrieve_authorization(
        self, auth_endpoint: GetAuthorizationEndpoint
    ) -> Authorization:
        """Retrieve an Authorization resource associated with the given endpoint.

        Parameters
        ----------
        auth_endpoint : GetAuthorizationEndpoint
            The Authorization endpoint to dereference.

        Returns
        -------
        Authorization
            The Authorization object as currently stored on the ACME server.

        Raises
        ------
        Exception
            When the server could not get the authorization resource.
        """
        response = auth_endpoint.retrieve(
            key=self.private_key,
            nonce=self.last_replay_nonce,
            kid=self.account_endpoint.url,
            payload="",
        )

        # Use replay nonce for future requests
        self.last_replay_nonce = response.headers["Replay-Nonce"]

        # The Retry-After header may exist if there's an update in progress to
        # this authorization. We'll respect this and retry.
        if "Retry-After" in response.headers:
            # We use the urllib3 retry-after parsing function since the value is
            # complex and can be int or date.
            wait_seconds = urllib3.Retry().parse_retry_after(
                response.headers["Retry-After"]
            )
            print(f"Waiting {wait_seconds} seconds to retry Authorization endpoint...")
            sleep(wait_seconds)
            return self._retrieve_authorization(auth_endpoint=auth_endpoint)

        # RFC Section 7.5 specifies it has to return 200 on success
        if response.status_code != 200:
            raise Exception(
                "Server could not get the authorization resource: " + response.text
            )

        return Authorization.from_json(response.json())

    def _class_as_json(self, instance: Any) -> str:
        """Use any custom to_json() method defined on the class, to create a JSON
        representation. If it doesn't exist, we naively call dataclasses.asdict.
        This method is only expected to be called on Stub dataclasses, which are
        the request bodies to send to the ACME server.

        Parameters
        ----------
        instance : Any
            A class instance to turn into JSON.

        Returns
        -------
        str
            The JSON representation of the class.
        """

        def _attempt_custom_json(obj: Any):
            try:
                return obj.to_json()
            except:
                return dataclasses.asdict(obj)

        return json.dumps(instance, default=_attempt_custom_json)
