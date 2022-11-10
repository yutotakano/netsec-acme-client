from dataclasses import dataclass
from dataclasses import field

from acme_project.acme_client.endpoint import Endpoint


@dataclass
class NewNonceEndpoint(Endpoint):
    url: str
    method: str = field(default="HEAD", init=False)
    headers: dict[str, str] = field(default_factory=dict, init=False)
