from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Optional

from acme_project.acme_client.authorization import GetAuthorizationEndpoint
from acme_project.acme_client.certificate import GetCertificateEndpoint
from acme_project.acme_client.endpoint import Endpoint


@dataclass
class NewOrderEndpoint(Endpoint):
    method: str = "POST"
    use_jwk: bool = False
    use_kid: bool = True

    def __init__(self, url: str):
        self.url = url


@dataclass
class ListOrdersEndpoint(Endpoint):
    method: str = "POST"
    use_jwk: bool = False
    use_kid: bool = True

    def __init__(self, url: str):
        self.url = url


@dataclass
class GetOrderEndpoint(Endpoint):
    method: str = "POST"
    use_jwk: bool = False
    use_kid: bool = True

    def __init__(self, url: str):
        self.url = url


@dataclass
class FinalizeOrderEndpoint(Endpoint):
    method: str = "POST"
    use_jwk: bool = False
    use_kid: bool = True

    def __init__(self, url: str):
        self.url = url


@dataclass
class Order:
    status: str
    expires: Optional[str]
    identifiers: list[dict[str, str]]
    not_before: Optional[str]
    not_after: Optional[str]
    error: Optional[dict[str, str]]
    authorization_urls: list[GetAuthorizationEndpoint]
    finalize: FinalizeOrderEndpoint
    certificate: Optional[GetCertificateEndpoint]

    @staticmethod
    def from_json(response_json: dict[str, Any]):
        return Order(
            status=response_json["status"],
            expires=response_json.get("expires", None),
            identifiers=response_json["identifiers"],
            not_before=response_json.get("notBefore", None),
            not_after=response_json.get("notAfter", None),
            error=response_json.get("error", None),
            authorization_urls=list(
                map(GetAuthorizationEndpoint, response_json["authorizations"])
            ),
            finalize=FinalizeOrderEndpoint(response_json["finalize"]),
            certificate=GetCertificateEndpoint(response_json.get("certificate", None))
            if "certificate" in response_json
            else None,
        )


@dataclass
class OrderStub:
    # RFC Section 7.4, for creating a new order
    identifiers: list[dict[str, str]] = field(default_factory=list)
    not_before: Optional[str] = field(default=None)
    not_after: Optional[str] = field(default=None)

    def to_json(self):
        return {
            "identifiers": self.identifiers,
            "notBefore": self.not_before,
            "notAfter": self.not_after,
        }
