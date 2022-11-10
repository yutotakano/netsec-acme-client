from dataclasses import dataclass
from typing import Any
from typing import Optional

from acme_project.acme_client.endpoint import Endpoint


@dataclass
class ChallengeResponseEndpoint(Endpoint):
    method: str = "POST"
    use_jwk: bool = False
    use_kid: bool = True

    def __init__(self, url: str):
        self.url = url


@dataclass
class Challenge:
    type: str
    respond_url: ChallengeResponseEndpoint
    status: str
    validated: Optional[str]
    error: Optional[dict[str, str]]
    additional: dict[str, str]

    @staticmethod
    def from_json(response_json: dict[str, Any]):
        # Use .pop to remove the fields gradually and get the additional fields
        # leftover for each challenge type.
        return Challenge(
            type=response_json.pop("type"),
            respond_url=ChallengeResponseEndpoint(response_json.pop("url")),
            status=response_json.pop("status"),
            validated=response_json.pop("validated", None),
            error=response_json.pop("error", None),
            additional=response_json,
        )
