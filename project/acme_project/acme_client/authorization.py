from dataclasses import dataclass
from typing import Any
from typing import Optional

from acme_project.acme_client.challenge import Challenge
from acme_project.acme_client.endpoint import Endpoint


@dataclass
class NewAuthzEndpoint(Endpoint):
    method: str = "POST"
    use_jwk: bool = False
    use_kid: bool = True

    def __init__(self, url: str):
        self.url = url


@dataclass
class GetAuthorizationEndpoint(Endpoint):
    method: str = "POST"
    use_jwk: bool = False
    use_kid: bool = True

    def __init__(self, url: str):
        self.url = url


@dataclass
class Authorization:
    identifier: dict[str, str]
    status: str
    expires: Optional[str]
    challenges: list[Challenge]
    wildcard: Optional[bool]

    @staticmethod
    def from_json(response_json: dict[str, Any]):
        return Authorization(
            identifier=response_json["identifier"],
            status=response_json["status"],
            expires=response_json.get("expires", None),
            challenges=list(map(Challenge.from_json, response_json["challenges"])),
            wildcard=response_json.get("wildcard", None),
        )
