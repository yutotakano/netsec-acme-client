from dataclasses import dataclass
from typing import Union

from acme_project.acme_client.account import NewAccountEndpoint
from acme_project.acme_client.authorization import NewAuthzEndpoint
from acme_project.acme_client.certificate import RevokeCertEndpoint
from acme_project.acme_client.endpoint import Endpoint
from acme_project.acme_client.key_change import KeyChangeEndpoint
from acme_project.acme_client.new_nonce import NewNonceEndpoint
from acme_project.acme_client.order import NewOrderEndpoint


@dataclass
class Directory:
    # RFC Section 7.1.1
    new_nonce_endpoint: NewNonceEndpoint
    new_account_endpoint: NewAccountEndpoint
    new_order_endpoint: NewOrderEndpoint
    new_authz_endpoint: NewAuthzEndpoint
    revoke_cert_endpoint: RevokeCertEndpoint
    key_change_endpoint: KeyChangeEndpoint

    metadata: dict[str, Union[str, bool, list[str]]]

    def __init__(self, dir_dict: dict[str, str]):
        self.new_nonce_endpoint = NewNonceEndpoint(dir_dict["newNonce"])
        self.new_account_endpoint = NewAccountEndpoint(dir_dict["newAccount"])
        self.new_order_endpoint = NewOrderEndpoint(dir_dict["newOrder"])
        self.new_authz_endpoint = NewAuthzEndpoint(dir_dict["newOrder"])
        self.revoke_cert_endpoint = RevokeCertEndpoint(dir_dict["revokeCert"])
        self.key_change_endpoint = KeyChangeEndpoint(dir_dict["keyChange"])
        self.metadata = dir_dict["meta"]  # type: ignore


@dataclass
class DirectoryEndpoint(Endpoint):
    url: str
    method: str = "GET"
    use_jwk: bool = False
    use_kid: bool = False

    def __init__(self, url: str):
        self.url = url
