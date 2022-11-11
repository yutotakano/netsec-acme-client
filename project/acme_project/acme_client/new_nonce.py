from dataclasses import dataclass

from acme_project.acme_client.endpoint import Endpoint


@dataclass
class NewNonceEndpoint(Endpoint):
    method: str = "HEAD"
    use_jwk: bool = False
    use_kid: bool = False

    def __init__(self, url: str):
        self.url = url
