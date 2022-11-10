from dataclasses import dataclass
from dataclasses import field
from typing import Any, Optional

from acme_project.acme_client.endpoint import Endpoint
from acme_project.acme_client.order import ListOrdersEndpoint


@dataclass
class Account:
    # RFC Section 7.1.2
    status: str
    contact: list[str]
    tos_agreed: Optional[bool]
    # external_account_binding:
    orders_url: ListOrdersEndpoint

    @staticmethod
    def from_json(response_json: dict[str, Any]):
        return Account(
            status=response_json["status"],
            contact=response_json.get("contact", []),
            tos_agreed=response_json.get("termsOfServiceAgreed", None),
            orders_url=ListOrdersEndpoint(response_json["orders"]),
        )


@dataclass
class AccountStub:
    # RFC Section 7.3, for requesting a new account
    status: str = field(default="")
    contact: list[str] = field(default_factory=list)
    tos_agreed: Optional[bool] = field(default=None)
    only_return_existing: Optional[bool] = field(default=None)
    external_account_binding: Optional[dict[str, str]] = field(default=None)

    def to_json(self):
        return {
            "status": self.status,
            "contact": self.contact,
            "termsOfServiceAgreed": self.tos_agreed,
            "onlyReturnExisting": self.only_return_existing,
            "externalAccountBinding": self.external_account_binding,
        }


@dataclass
class NewAccountEndpoint(Endpoint):
    method: str = "POST"
    use_jwk: bool = True
    use_kid: bool = False

    def __init__(self, url: str):
        self.url = url


@dataclass
class MainAccountEndpoint(Endpoint):
    method: str = "POST"
    use_jwk: bool = False
    use_kid: bool = True

    def __init__(self, url: str):
        self.url = url
